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

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The lockout against a real Redis: a lock per (username, IP) that a spray cannot turn into a lockout of the victim
 * from elsewhere, plus the per-account and per-IP ceilings, the window and lock TTLs, and the password-change limit.
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

    private void fail(String username, String ip, int times) {
        for (int i = 0; i < times; i++) {
            limiter.recordFailure(username, from(ip));
        }
    }

    private void assertLocked(String username, String ip) {
        assertThatThrownBy(() -> limiter.assertAllowed(username, from(ip)))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.getRetryAfterSeconds()).isEqualTo(LoginRateLimiter.LOCK_SECONDS);
                });
    }

    private void assertAllowed(String username, String ip) {
        assertThatCode(() -> limiter.assertAllowed(username, from(ip))).doesNotThrowAnyException();
    }

    private long ttl(String key) {
        return redis.getExpire(key, TimeUnit.SECONDS);
    }

    @Test
    void pairLockDoesNotSpillToAnotherIp() {
        fail("alice", "10.0.0.1", 4);
        assertAllowed("alice", "10.0.0.1");

        fail("alice", "10.0.0.1", 1);

        assertLocked("alice", "10.0.0.1");
        assertAllowed("alice", "10.0.0.2");
        assertAllowed("bob", "10.0.0.1");
    }

    @Test
    void thirtyFailuresLockTheIp() {
        for (int i = 0; i < 29; i++) {
            limiter.recordFailure("user" + i, from("10.0.0.1"));
        }
        assertAllowed("newuser", "10.0.0.1");

        limiter.recordFailure("user29", from("10.0.0.1"));

        assertLocked("newuser", "10.0.0.1");
        assertAllowed("newuser", "10.0.0.2");
    }

    @Test
    void fiftyFailuresLockTheAccount() {
        for (int i = 1; i <= 49; i++) {
            limiter.recordFailure("alice", from("10.1.0." + i));
        }
        assertAllowed("alice", "10.9.9.9");

        limiter.recordFailure("alice", from("10.1.0.50"));

        assertLocked("alice", "10.9.9.9");
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
    void recordFailureReturnsTheBackoffOfThePairsOwnCount() {
        // Ten failures of alice elsewhere raise her account counter but not this pair's.
        for (int i = 1; i <= 10; i++) {
            limiter.recordFailure("alice", from("10.2.0." + i));
        }

        assertThat(limiter.recordFailure("alice", from("10.0.0.1"))).isZero();
        assertThat(limiter.recordFailure("alice", from("10.0.0.1"))).isZero();
        assertThat(limiter.recordFailure("alice", from("10.0.0.1"))).isZero();
        assertThat(limiter.recordFailure("alice", from("10.0.0.1"))).isEqualTo(Duration.ofSeconds(2));
        assertThat(limiter.recordFailure("alice", from("10.0.0.1"))).isEqualTo(Duration.ofSeconds(4));
    }

    @Test
    void clearForgetsThePairOnly() {
        fail("alice", "10.0.0.1", 3);

        limiter.clear("alice", from("10.0.0.1"));

        assertThat(redis.hasKey("oj:rl:login:pair:alice|10.0.0.1")).isFalse();
        assertThat(redis.opsForValue().get("oj:rl:login:account:alice")).isEqualTo("3");
        assertThat(redis.opsForValue().get("oj:rl:login:ip:10.0.0.1")).isEqualTo("3");
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
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.getRetryAfterSeconds()).isEqualTo(LoginRateLimiter.LOCK_SECONDS);
                });
        assertThatCode(() -> limiter.assertPasswordChangeAllowed(someoneElse)).doesNotThrowAnyException();
        assertThat(ttl("oj:rl:login:pwchange:" + me)).isBetween(290L, 300L);
        assertThat(ttl("oj:rl:lock:pwchange:" + me)).isBetween(890L, 900L);
    }
}
