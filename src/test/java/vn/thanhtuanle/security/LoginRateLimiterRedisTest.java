package vn.thanhtuanle.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The lockout against a real Redis. Every attempt reserves its place in the pair, account and IP counters before the
 * password is checked, so a burst cannot get past a limit. A lock per (username, IP) means a spray cannot lock the
 * victim out from elsewhere; the account and IP ceilings, the window and lock TTLs and the password-change limit
 * complete it.
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
        limiter = new LoginRateLimiter(redis, new SimpleMeterRegistry());
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
                    assertThat(e.getRetryAfterSeconds()).isBetween(1L, LoginRateLimiter.ACCOUNT_WINDOW.toSeconds());
                });
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
    void theSixthAttemptInFlightIsRefusedBeforeItsPasswordIsChecked() {
        // Five attempts reserved, none answered yet: a burst that all passed one look at the locks.
        for (int i = 1; i <= 5; i++) {
            assertThat(limiter.reserve("alice", from("10.0.0.1")).pairCount()).isEqualTo(i);
        }

        assertThatThrownBy(() -> limiter.reserve("alice", from("10.0.0.1")))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        // No lock yet: retry once the pair's window has passed.
                        assertThat(e.getRetryAfterSeconds()).isBetween(290L, 300L));
        assertThat(value("oj:rl:login:pair:alice|10.0.0.1")).isEqualTo("5");
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
            assertThat(admitted).isEqualTo(5);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void thirtyFailuresLockTheIp() {
        for (int i = 0; i < 29; i++) {
            fail("user" + i, "10.0.0.1");
        }
        assertThat(redis.hasKey("oj:rl:lock:ip:10.0.0.1")).isFalse();

        fail("user29", "10.0.0.1");

        assertRefused("newuser", "10.0.0.1");
        assertAllowed("newuser", "10.0.0.2");
    }

    @Test
    void fiftyFailuresLockTheAccount() {
        for (int i = 1; i <= 49; i++) {
            fail("alice", "10.1.0." + i);
        }
        assertThat(redis.hasKey("oj:rl:lock:account:alice")).isFalse();

        fail("alice", "10.1.0.50");

        assertRefused("alice", "10.9.9.9");
        // Fifty per hour: the account stays refused while its hour lasts, even after the 15-minute lock.
        assertThatThrownBy(() -> limiter.reserve("alice", from("10.9.9.8")))
                .isInstanceOfSatisfying(RateLimitedException.class, e ->
                        assertThat(e.getRetryAfterSeconds()).isBetween(3590L, 3600L));
        assertAllowed("bob", "10.9.9.9");
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
    void aSuccessForgivesThePairAndHandsBackItsAccountAndIpPlaces() {
        fail("alice", "10.0.0.1", 2);
        Attempt success = limiter.reserve("alice", from("10.0.0.1"));

        limiter.recordSuccess(success);

        assertThat(redis.hasKey("oj:rl:login:pair:alice|10.0.0.1")).isFalse();
        // A success is not a failure: only the two failures still count.
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
