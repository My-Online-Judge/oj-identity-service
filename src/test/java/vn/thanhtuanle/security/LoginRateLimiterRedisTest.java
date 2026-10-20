package vn.thanhtuanle.security;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.security.LoginRateLimiter.Attempt;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The lockout against a real Redis. Every attempt reserves its place in the pair and account counters before the
 * password is checked, so a burst cannot get past a limit. A lock per (username, IP) means a spray cannot lock the
 * victim out from elsewhere; the account ceiling, the address's ceiling on failures (correct logins never count toward
 * it), the window and lock TTLs and the password-change limit complete it.
 */
@Testcontainers(disabledWithoutDocker = true)
class LoginRateLimiterRedisTest {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;

    private LoginRateLimiter limiter;

    @BeforeAll
    static void connect() {
        connections = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connections.afterPropertiesSet();
        redis = new StringRedisTemplate(connections);
    }

    @AfterAll
    static void disconnect() {
        connections.destroy();
    }

    @BeforeEach
    void flush() {
        redis.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushAll();
            return null;
        });
        limiter = new LoginRateLimiter(redis, new SimpleMeterRegistry(), 30);
    }

    private static ClientMeta from(String ip) {
        return new ClientMeta(ip, "dev-1", "probe/1.0");
    }

    /** One failed login: reserve, then the wrong password. */
    private Duration fail(String username, String ip) {
        return limiter.recordFailure(limiter.reserve(username, from(ip)));
    }

    private void fail(String username, String ip, int times) {
        for (int i = 0; i < times; i++) {
            fail(username, ip);
        }
    }

    private void assertRefused(String username, String ip) {
        assertThatThrownBy(() -> limiter.reserve(username, from(ip)))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED);
                    // Only a lock refuses, so Retry-After is never above the lock's 15 minutes.
                    assertThat(e.getRetryAfterSeconds()).isBetween(1L, LoginRateLimiter.LOCK_SECONDS);
                });
    }

    private void assertRetryAfter(String username, String ip, long atLeast, long atMost) {
        assertThatThrownBy(() -> limiter.reserve(username, from(ip)))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(atLeast, atMost));
    }

    private void assertAllowed(String username, String ip) {
        assertThatCode(() -> limiter.reserve(username, from(ip))).doesNotThrowAnyException();
    }

    private long ttl(String key) {
        return redis.getExpire(key, TimeUnit.SECONDS);
    }

    private String value(String key) {
        return redis.opsForValue().get(key);
    }

    @Test
    void pairLockDoesNotSpillToAnotherIp() {
        fail("alice", "10.0.0.1", 4);
        assertThat(redis.hasKey("oj:rl:lock:pair:alice|10.0.0.1")).isFalse();

        fail("alice", "10.0.0.1");

        assertRefused("alice", "10.0.0.1");
        assertAllowed("alice", "10.0.0.2");
        assertAllowed("bob", "10.0.0.1");
    }

    @Test
    void aBurstGetsThePairLimitPlusOneProbe_thenEveryAttemptIsRefusedBeforeItsPasswordIsChecked() {
        // Five attempts reserved, none answered yet: a burst that all passed one look at the locks.
        for (int i = 1; i <= 5; i++) {
            assertThat(limiter.reserve("alice", from("10.0.0.1")).pairCount()).isEqualTo(i);
        }
        assertThat(redis.hasKey("oj:rl:lock:pair:alice|10.0.0.1")).isFalse();

        // The sixth goes over the limit: it locks the pair in the same step and is let through as the one probe.
        Attempt probe = limiter.reserve("alice", from("10.0.0.1"));
        assertThat(probe.pairCount()).isEqualTo(6);
        // A probe's lock only outlives the probe if identity dies mid-probe, so it lasts 60 s, not 15 minutes.
        assertThat(ttl("oj:rl:lock:pair:alice|10.0.0.1")).isBetween(50L, 60L);
        assertThat(value("oj:rl:lock:pair:alice|10.0.0.1")).startsWith("probe:").isEqualTo(probe.probeToken());

        // Refused while the probe is in flight: it usually settles within a second, so "retry in 2 s", not 15 min.
        assertRetryAfter("alice", "10.0.0.1", 2, 2);
        assertThat(value("oj:rl:login:pair:alice|10.0.0.1")).isEqualTo("6");
    }

    @Test
    void fortyConcurrentCorrectLoginsFromOneAddress_noneIsRefused() throws Exception {
        // A hall behind one NAT address signs in at once: every login is in flight (BCrypt queued) at the same time.
        int students = 40;
        ExecutorService pool = Executors.newFixedThreadPool(students);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Attempt>> results = new ArrayList<>();
        try {
            for (int i = 0; i < students; i++) {
                String username = "student" + i;
                results.add(pool.submit(() -> {
                    start.await();
                    return limiter.reserve(username, from("10.0.0.1"));
                }));
            }
            start.countDown();
            List<Attempt> admitted = new ArrayList<>();
            for (Future<Attempt> result : results) {
                admitted.add(result.get(10, TimeUnit.SECONDS)); // a refusal would surface as an ExecutionException
            }
            admitted.forEach(limiter::recordSuccess);
        } finally {
            pool.shutdownNow();
        }

        // Correct logins never count toward the address's limit, in flight or after.
        assertThat(redis.hasKey("oj:rl:lock:ip:10.0.0.1")).isFalse();
        assertThat(redis.hasKey("oj:rl:login:ip:10.0.0.1")).isFalse();
        assertAllowed("student40", "10.0.0.1");
    }

    @Test
    void anAddressCountsFailuresOnly() {
        fail("alice", "10.0.0.1", 2);
        for (int i = 0; i < 100; i++) {
            limiter.recordSuccess(limiter.reserve("student" + i, from("10.0.0.1")));
        }
        Attempt inFlight = limiter.reserve("bob", from("10.0.0.1"));

        assertThat(value("oj:rl:login:ip:10.0.0.1")).isEqualTo("2");
        assertThat(inFlight.pairCount()).isEqualTo(1);
    }

    @Test
    void aProbeLock_expiresAfterSixtySeconds_butAFailedProbeLeavesAFifteenMinuteFailLock() {
        for (int i = 1; i <= 5; i++) {
            limiter.reserve("alice", from("10.0.0.1"));
        }
        Attempt probe = limiter.reserve("alice", from("10.0.0.1"));
        assertThat(probe.pairProbe()).isTrue();
        assertThat(ttl("oj:rl:lock:pair:alice|10.0.0.1")).isLessThanOrEqualTo(60L);
        assertRetryAfter("alice", "10.0.0.1", 2, 2);

        // The probe's password is wrong: its lock becomes a failure's, for the full 15 minutes.
        limiter.recordFailure(probe);

        assertThat(value("oj:rl:lock:pair:alice|10.0.0.1")).startsWith("fail:");
        assertThat(ttl("oj:rl:lock:pair:alice|10.0.0.1")).isBetween(890L, 900L);
        assertRetryAfter("alice", "10.0.0.1", 899, 900);
    }

    @Test
    void aRefusalOnAFailureLock_answersWhatIsLeftOfIt() {
        fail("alice", "10.0.0.1", 5);
        assertThat(value("oj:rl:lock:pair:alice|10.0.0.1")).startsWith("fail:");

        assertRetryAfter("alice", "10.0.0.1", 899, 900);

        // A lock written before locks carried a token ("1") is a failure's lock too.
        redis.opsForValue().set("oj:rl:lock:ip:10.0.0.9", "1", Duration.ofSeconds(120));
        assertRetryAfter("bob", "10.0.0.9", 119, 120);
    }

    /**
     * A probe's lock and a failure's lock refusing the same attempt: the answer is the longest wait, so a failure's
     * 15 minutes are never hidden behind a probe's "retry in 2 s", whichever key comes first; and a failure's lock with
     * less than 2 s left still answers 2.
     */
    @Test
    void aProbeLockAndAFailureLockRefusingOneAttempt_answerTheLongerWait() {
        redis.opsForValue().set("oj:rl:lock:pair:alice|10.0.0.1", "fail:x", Duration.ofMinutes(15));
        redis.opsForValue().set("oj:rl:lock:account:alice", "probe:y", Duration.ofSeconds(60));
        assertRetryAfter("alice", "10.0.0.1", 899, 900);

        redis.opsForValue().set("oj:rl:lock:account:bob", "probe:y", Duration.ofSeconds(60));
        redis.opsForValue().set("oj:rl:lock:ip:10.0.0.2", "fail:x", Duration.ofMinutes(15));
        assertRetryAfter("bob", "10.0.0.2", 899, 900);

        redis.opsForValue().set("oj:rl:lock:pair:carol|10.0.0.3", "fail:x", Duration.ofSeconds(1));
        redis.opsForValue().set("oj:rl:lock:account:carol", "probe:y", Duration.ofSeconds(60));
        assertRetryAfter("carol", "10.0.0.3", 2, 2);
    }

    @Test
    void aFailureInFlightThatLocksAgain_survivesTheProbesSuccess() {
        fail("alice", "10.0.0.1", 4);
        Attempt fifth = limiter.reserve("alice", from("10.0.0.1"));
        Attempt probe = limiter.reserve("alice", from("10.0.0.1"));
        assertThat(probe.pairProbe()).isTrue();

        // The fifth was still being checked when the probe was let through; it fails and locks the pair itself.
        limiter.recordFailure(fifth);
        limiter.recordSuccess(probe);

        // The probe lifts only its own lock: the failure's lock stays for its 15 minutes.
        assertThat(value("oj:rl:lock:pair:alice|10.0.0.1")).startsWith("fail:");
        assertRetryAfter("alice", "10.0.0.1", 899, 900);
    }

    @Test
    void concurrentReservationsAdmitExactlyThePairLimit() throws Exception {
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                Callable<Boolean> attempt = () -> {
                    start.await();
                    try {
                        limiter.reserve("alice", from("10.0.0.1"));
                        return true;
                    } catch (RateLimitedException refused) {
                        return false;
                    }
                };
                results.add(pool.submit(attempt));
            }
            start.countDown();
            int admitted = 0;
            for (Future<Boolean> result : results) {
                admitted += result.get(10, TimeUnit.SECONDS) ? 1 : 0;
            }
            assertThat(admitted).as("the pair's five plus one probe").isEqualTo(6);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentReservationsAdmitExactlyTheAccountLimitPlusOne() throws Exception {
        int threads = 60;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                String address = "10.3.0." + i;
                Callable<Boolean> attempt = () -> {
                    start.await();
                    try {
                        limiter.reserve("alice", from(address));
                        return true;
                    } catch (RateLimitedException refused) {
                        return false;
                    }
                };
                results.add(pool.submit(attempt));
            }
            start.countDown();
            int admitted = 0;
            for (Future<Boolean> result : results) {
                admitted += result.get(10, TimeUnit.SECONDS) ? 1 : 0;
            }
            assertThat(admitted).as("the account's fifty plus one probe").isEqualTo(51);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void thirtyFailuresFromOneAddressLockIt_andTheThirtyFirstAttemptIsToldWhatIsLeftOfTheLock() {
        for (int i = 0; i < 29; i++) {
            fail("user" + i, "10.0.0.1");
        }
        assertThat(redis.hasKey("oj:rl:lock:ip:10.0.0.1")).isFalse();

        fail("user29", "10.0.0.1");

        assertThat(value("oj:rl:lock:ip:10.0.0.1")).startsWith("fail:");
        assertThat(ttl("oj:rl:lock:ip:10.0.0.1")).isBetween(890L, 900L);
        assertRetryAfter("newuser", "10.0.0.1", 899, 900);
        assertAllowed("newuser", "10.0.0.2");
    }

    @Test
    void theIpLimitIsTheConfiguredOne() {
        LoginRateLimiter lab = new LoginRateLimiter(redis, new SimpleMeterRegistry(), 3);
        lab.recordFailure(lab.reserve("user0", from("10.0.0.1")));
        lab.recordFailure(lab.reserve("user1", from("10.0.0.1")));
        assertThat(redis.hasKey("oj:rl:lock:ip:10.0.0.1")).isFalse();

        lab.recordFailure(lab.reserve("user2", from("10.0.0.1")));

        assertThatThrownBy(() -> lab.reserve("user3", from("10.0.0.1")))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(899L, 900L));
    }

    /** The limiter as the application builds it, with this test's Redis and the given configuration. */
    private ApplicationContextRunner application() {
        return new ApplicationContextRunner()
                .withBean(StringRedisTemplate.class, () -> redis)
                .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
                .withBean(LoginRateLimiter.class);
    }

    private static final AtomicInteger ADDRESSES = new AtomicInteger();

    /** Whether {@code failures} failures from one fresh address lock it. */
    private static boolean failuresLockAnAddress(LoginRateLimiter limiter, int failures) {
        String address = "10.7.0." + ADDRESSES.incrementAndGet();
        for (int i = 0; i < failures; i++) {
            limiter.recordFailure(limiter.reserve("user" + i, from(address)));
        }
        return redis.hasKey("oj:rl:lock:ip:" + address);
    }

    @Test
    void theIpLimitIsOjLoginIpLimit_settableAsOJ_LOGIN_IP_LIMIT_andThirtyByDefault() {
        application().run(context -> {
            LoginRateLimiter byDefault = context.getBean(LoginRateLimiter.class);
            assertThat(failuresLockAnAddress(byDefault, 29)).isFalse();
            assertThat(failuresLockAnAddress(byDefault, 30)).isTrue();
        });
        application().withPropertyValues("oj.login.ip-limit=3").run(context ->
                assertThat(failuresLockAnAddress(context.getBean(LoginRateLimiter.class), 3)).isTrue());
        // How .env.identity sets it: an environment variable, bound the way Spring Boot binds them.
        application()
                .withInitializer(context -> {
                    ConfigurableEnvironment environment = context.getEnvironment();
                    environment.getPropertySources().replace(
                            StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                            new SystemEnvironmentPropertySource(
                                    StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                                    Map.of("OJ_LOGIN_IP_LIMIT", "4")));
                    ConfigurationPropertySources.attach(environment);
                })
                .run(context -> {
                    LoginRateLimiter fromEnv = context.getBean(LoginRateLimiter.class);
                    assertThat(failuresLockAnAddress(fromEnv, 3)).isFalse();
                    assertThat(failuresLockAnAddress(fromEnv, 4)).isTrue();
                });
    }

    @Test
    void fiftyFailuresLockTheAccount() {
        for (int i = 1; i <= 49; i++) {
            fail("alice", "10.1.0." + i);
        }
        assertThat(redis.hasKey("oj:rl:lock:account:alice")).isFalse();

        fail("alice", "10.1.0.50");

        assertRefused("alice", "10.9.9.9");
        assertThatThrownBy(() -> limiter.reserve("alice", from("10.9.9.8")))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(899L, 900L));
        assertAllowed("bob", "10.9.9.9");
    }

    /** Fifty failures from 50 addresses, then the account's 15-minute lock runs out (its hour has not). */
    private void accountLockedThenExpired() {
        for (int i = 1; i <= 50; i++) {
            fail("alice", "10.1.0." + i);
        }
        assertThat(redis.hasKey("oj:rl:lock:account:alice")).isTrue();
        redis.delete("oj:rl:lock:account:alice");
        assertThat(value("oj:rl:login:account:alice")).isEqualTo("50");
    }

    @Test
    void afterTheAccountLockExpires_oneProbeIsLetThrough_andLocksAgainForEveryoneElse() {
        accountLockedThenExpired();

        Attempt probe = limiter.reserve("alice", from("10.9.9.9"));

        assertThat(probe.accountCount()).isEqualTo(51);
        assertThat(ttl("oj:rl:lock:account:alice")).isBetween(50L, 60L);
        assertRefused("alice", "10.9.9.8");
    }

    @Test
    void aSuccessfulProbe_liftsTheLockItSet() {
        accountLockedThenExpired();
        Attempt probe = limiter.reserve("alice", from("10.9.9.9"));

        limiter.recordSuccess(probe);

        // The legitimate user is in, and the account is open again (its earlier failures still count).
        assertThat(redis.hasKey("oj:rl:lock:account:alice")).isFalse();
        assertThat(value("oj:rl:login:account:alice")).isEqualTo("50");
        assertAllowed("alice", "10.9.9.8");
    }

    @Test
    void aReleaseHandsBackEveryPlace_thePairsIncluded() {
        fail("alice", "10.0.0.1", 2);
        Attempt busy = limiter.reserve("alice", from("10.0.0.1"));

        // Not a verdict on the password (the account was busy, or something broke): not a failure, and no typo
        // forgiven either.
        limiter.release(busy);

        assertThat(value("oj:rl:login:pair:alice|10.0.0.1")).isEqualTo("2");
        assertThat(value("oj:rl:login:account:alice")).isEqualTo("2");
        assertThat(value("oj:rl:login:ip:10.0.0.1")).isEqualTo("2");
    }

    @Test
    void aReleasedProbe_liftsTheLockItSet() {
        accountLockedThenExpired();
        Attempt probe = limiter.reserve("alice", from("10.9.9.9"));
        assertThat(probe.accountProbe()).isTrue();
        assertThat(probe.pairProbe()).isFalse();

        limiter.release(probe);

        assertThat(redis.hasKey("oj:rl:lock:account:alice")).isFalse();
        assertThat(value("oj:rl:login:account:alice")).isEqualTo("50");
    }

    @Test
    void aWrongProbe_locksForAnotherFifteenMinutes() {
        accountLockedThenExpired();

        fail("alice", "10.9.9.9");

        assertThat(ttl("oj:rl:lock:account:alice")).isBetween(890L, 900L);
        assertRetryAfter("alice", "10.9.9.8", 899, 900);
    }

    @Test
    void ttls() {
        fail("alice", "10.0.0.1", 5);

        assertThat(ttl("oj:rl:login:pair:alice|10.0.0.1")).isBetween(290L, 300L);
        assertThat(ttl("oj:rl:login:ip:10.0.0.1")).isBetween(290L, 300L);
        assertThat(ttl("oj:rl:login:account:alice")).isBetween(3590L, 3600L);
        assertThat(ttl("oj:rl:lock:pair:alice|10.0.0.1")).isBetween(890L, 900L);
    }

    @Test
    void retryAfterIsWhatIsLeftOfTheLock() {
        fail("alice", "10.0.0.1", 5);
        redis.expire("oj:rl:lock:pair:alice|10.0.0.1", Duration.ofSeconds(30));
        redis.expire("oj:rl:login:pair:alice|10.0.0.1", Duration.ofSeconds(10));

        assertThatThrownBy(() -> limiter.reserve("alice", from("10.0.0.1")))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(29L, 30L));
    }

    @Test
    void recordFailureReturnsTheBackoffOfThePairsOwnCount() {
        // Ten failures of alice elsewhere raise her account counter but not this pair's.
        for (int i = 1; i <= 10; i++) {
            fail("alice", "10.2.0." + i);
        }

        assertThat(fail("alice", "10.0.0.1")).isZero();
        assertThat(fail("alice", "10.0.0.1")).isZero();
        assertThat(fail("alice", "10.0.0.1")).isZero();
        assertThat(fail("alice", "10.0.0.1")).isEqualTo(Duration.ofSeconds(2));
        assertThat(fail("alice", "10.0.0.1")).isEqualTo(Duration.ofSeconds(4));
    }

    @Test
    void aSuccessForgivesThePairAndHandsBackItsAccountPlace() {
        fail("alice", "10.0.0.1", 2);
        Attempt success = limiter.reserve("alice", from("10.0.0.1"));

        limiter.recordSuccess(success);

        assertThat(redis.hasKey("oj:rl:login:pair:alice|10.0.0.1")).isFalse();
        // A success is not a failure: only the two failures still count (the address counted nothing else).
        assertThat(value("oj:rl:login:account:alice")).isEqualTo("2");
        assertThat(value("oj:rl:login:ip:10.0.0.1")).isEqualTo("2");
        assertThat(ttl("oj:rl:login:account:alice")).isBetween(3590L, 3600L);
    }

    @Test
    void aSuccessAfterTheCountersExpiredLeavesNothingBehind() {
        Attempt success = limiter.reserve("alice", from("10.0.0.1"));
        redis.delete(List.of("oj:rl:login:pair:alice|10.0.0.1", "oj:rl:login:account:alice", "oj:rl:login:ip:10.0.0.1"));

        limiter.recordSuccess(success);

        // No counter is left at -1 without a TTL to hand out extra attempts forever.
        assertThat(redis.hasKey("oj:rl:login:account:alice")).isFalse();
        assertThat(redis.hasKey("oj:rl:login:ip:10.0.0.1")).isFalse();
    }

    @Test
    void passwordChangeLocksAfterFive() {
        UUID me = UUID.randomUUID();
        UUID someoneElse = UUID.randomUUID();
        for (int i = 0; i < 4; i++) {
            limiter.recordPasswordChangeFailure(me);
        }
        assertThatCode(() -> limiter.assertPasswordChangeAllowed(me)).doesNotThrowAnyException();

        limiter.recordPasswordChangeFailure(me);

        assertThatThrownBy(() -> limiter.assertPasswordChangeAllowed(me))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    // Its own message: this is not about failed logins.
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PASSWORD_CHANGE_RATE_LIMITED);
                    assertThat(e.getErrorCode().getStatusCode().value()).isEqualTo(429);
                    assertThat(e.getRetryAfterSeconds()).isBetween(899L, 900L);
                });
        assertThatCode(() -> limiter.assertPasswordChangeAllowed(someoneElse)).doesNotThrowAnyException();
        assertThat(ttl("oj:rl:login:pwchange:" + me)).isBetween(290L, 300L);
        assertThat(ttl("oj:rl:lock:pwchange:" + me)).isBetween(890L, 900L);

        redis.expire("oj:rl:lock:pwchange:" + me, Duration.ofSeconds(42));
        assertThatThrownBy(() -> limiter.assertPasswordChangeAllowed(me))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(41L, 42L));
    }
}
