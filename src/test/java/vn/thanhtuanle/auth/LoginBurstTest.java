package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.user.UserRepository;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

/**
 * Parallel guesses against one account from one address, with the real limiter on a real Redis (H2 for the rest).
 * Every attempt reserves its place before its password is checked, so only the pair's five and one probe get a BCrypt
 * check; the rest are refused at once instead of passing one look at the locks together. After a lock runs out, the
 * right password signs in again. Correct logins never count toward the address's limit, so a hall behind one address
 * signs in at once.
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class LoginBurstTest {

    private static final int BURST = 20;
    private static final ClientMeta META = new ClientMeta("10.0.0.7", "dev-1", "burst/1.0");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @DynamicPropertySource
    static void redis(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @Autowired AuthService authService;
    @Autowired UserRepository userRepository;
    @Autowired StringRedisTemplate redis;

    @MockitoSpyBean PasswordEncoder passwordEncoder;
    @MockitoBean Sleeper sleeper;

    @Test
    void aBurstOfGuessesGetsOnlyThePairLimitOfPasswordChecks() throws Exception {
        String username = seedUser();
        AtomicInteger checked = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        // Hold every password check until the whole burst has either reached one or been refused.
        doAnswer(invocation -> {
            checked.incrementAndGet();
            release.await(20, TimeUnit.SECONDS);
            return invocation.callRealMethod();
        }).when(passwordEncoder).matches(any(), any());

        ExecutorService pool = Executors.newFixedThreadPool(BURST);
        List<Future<?>> attempts = new ArrayList<>();
        try {
            for (int i = 0; i < BURST; i++) {
                String guess = "Guess" + i + "x1";
                attempts.add(pool.submit(() -> {
                    try {
                        authService.authenticateWithPassword(username, guess, META);
                    } catch (RateLimitedException e) {
                        refused.incrementAndGet();
                    }
                    return null;
                }));
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (checked.get() + refused.get() < BURST && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            release.countDown();
            for (Future<?> attempt : attempts) {
                try {
                    attempt.get(20, TimeUnit.SECONDS);
                } catch (ExecutionException e) {
                    assertThat(e.getCause()).isInstanceOf(AppException.class); // a wrong password: 401
                }
            }
        } finally {
            pool.shutdownNow();
        }

        // The pair's five, plus the one that went over the limit and locked it as it passed: the probe.
        assertThat(checked.get()).as("password checks").isEqualTo(6);
        assertThat(refused.get()).as("refused before their password was checked").isEqualTo(BURST - 6);
    }

    /**
     * A hall of 40 behind one NAT address signs in at "go", every password right. Every check is held until all 40
     * have reached one or been refused, so they are all in flight at once: none is refused, because only failed
     * checks count toward the address's limit (30).
     */
    @Test
    void fortyConcurrentCorrectLoginsFromOneAddressAllSignIn() throws Exception {
        int hall = 40;
        String hash = passwordEncoder.encode("Secret123");
        List<String> students = new ArrayList<>();
        for (int i = 0; i < hall; i++) {
            students.add(seedUser(hash));
        }
        AtomicInteger checked = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        AtomicInteger signedIn = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            checked.incrementAndGet();
            release.await(20, TimeUnit.SECONDS);
            return invocation.callRealMethod();
        }).when(passwordEncoder).matches(any(), any());

        ExecutorService pool = Executors.newFixedThreadPool(hall);
        List<Future<?>> attempts = new ArrayList<>();
        try {
            for (String student : students) {
                attempts.add(pool.submit(() -> {
                    try {
                        if (authService.authenticateWithPassword(student, "Secret123", META).getAccessToken() != null) {
                            signedIn.incrementAndGet();
                        }
                    } catch (RateLimitedException e) {
                        refused.incrementAndGet();
                    }
                    return null;
                }));
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (checked.get() + refused.get() < hall && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            release.countDown();
            for (Future<?> attempt : attempts) {
                attempt.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(refused.get()).as("refused").isZero();
        assertThat(signedIn.get()).as("signed in").isEqualTo(hall);
        assertThat(redis.hasKey("oj:rl:lock:ip:" + META.ip())).isFalse();
    }

    @Test
    void afterTheAccountLockExpiresTheRightPasswordSignsIn() {
        String username = seedUser();
        // Fifty failures this hour; their 15-minute lock has run out.
        redis.opsForValue().set("oj:rl:login:account:" + username, "50", Duration.ofMinutes(40));

        AuthResponse tokens = authService.authenticateWithPassword(username, "Secret123", META);

        assertThat(tokens.getAccessToken()).isNotNull();
        // The probe's own lock is lifted again, so the account is open; its failures still count.
        assertThat(redis.hasKey("oj:rl:lock:account:" + username)).isFalse();
        assertThat(redis.opsForValue().get("oj:rl:login:account:" + username)).isEqualTo("50");
    }

    private String seedUser() {
        return seedUser(passwordEncoder.encode("Secret123"));
    }

    private String seedUser(String passwordHash) {
        String username = "burst_" + UUID.randomUUID().toString().substring(0, 8);
        userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordHash)
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
        return username;
    }
}
