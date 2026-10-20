package vn.thanhtuanle.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** The limiter's own logic with Redis mocked; the key formats and TTLs are pinned by LoginRateLimiterRedisTest. */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LoginRateLimiterTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "probe/1.0");

    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> valueOps;

    SimpleMeterRegistry registry;
    LoginRateLimiter limiter;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        when(redis.opsForValue()).thenReturn(valueOps);
        when(redis.countExistingKeys(anyCollection())).thenReturn(0L);
        limiter = new LoginRateLimiter(redis, registry);
    }

    private double fallbacks() {
        return registry.counter("oj.redis.fallback", "lookup", "login").count();
    }

    @Test
    void backoffSchedule() {
        assertThat(LoginRateLimiter.backoff(1)).isZero();
        assertThat(LoginRateLimiter.backoff(2)).isZero();
        assertThat(LoginRateLimiter.backoff(3)).isZero();
        assertThat(LoginRateLimiter.backoff(4)).isEqualTo(Duration.ofSeconds(2));
        assertThat(LoginRateLimiter.backoff(5)).isEqualTo(Duration.ofSeconds(4));
        assertThat(LoginRateLimiter.backoff(6)).isEqualTo(Duration.ofSeconds(8));
        assertThat(LoginRateLimiter.backoff(9)).isEqualTo(Duration.ofSeconds(8));
        // 2^(n-3) as a shift would wrap around for large n; the cap must hold however many requests raced past.
        assertThat(LoginRateLimiter.backoff(1_000)).isEqualTo(Duration.ofSeconds(8));
    }

    @Test
    void recordFailure_returnsTheBackoffOfThePairCount_notOfTheAccountOrIp() {
        when(valueOps.increment("oj:rl:login:pair:alice|1.2.3.4")).thenReturn(4L);
        when(valueOps.increment("oj:rl:login:account:alice")).thenReturn(40L);
        when(valueOps.increment("oj:rl:login:ip:1.2.3.4")).thenReturn(20L);

        assertThat(limiter.recordFailure("alice", META)).isEqualTo(Duration.ofSeconds(2));
    }

    @Test
    void lockedLogin_is429WithTheLockLengthAsRetryAfter() {
        when(redis.countExistingKeys(anyCollection())).thenReturn(1L);

        // A RateLimitedException, so the shared handler answers 429 with Retry-After = the lock's length.
        assertThatThrownBy(() -> limiter.assertAllowed("alice", META))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.getRetryAfterSeconds()).isEqualTo(LoginRateLimiter.LOCK_SECONDS);
                });
        assertThat(registry.counter("oj.login.rate_limited").count()).isEqualTo(1);
    }

    @Test
    void redisDown_failsOpen() {
        when(redis.countExistingKeys(anyCollection())).thenThrow(new RedisConnectionFailureException("redis down"));

        assertThatCode(() -> limiter.assertAllowed("alice", META)).doesNotThrowAnyException();
        // Counted, so the RedisUnavailable alert covers identity like the gateway and submission.
        assertThat(fallbacks()).isEqualTo(1);
    }

    @Test
    void redisDown_everyCallFailsOpen_withNoDelay_andIsCounted() {
        RedisConnectionFailureException down = new RedisConnectionFailureException("redis down");
        when(valueOps.increment(anyString())).thenThrow(down);
        when(redis.delete(anyString())).thenThrow(down);
        when(redis.countExistingKeys(anyCollection())).thenThrow(down);
        when(redis.hasKey(any())).thenThrow(down);
        UUID userId = UUID.randomUUID();

        assertThat(limiter.recordFailure("alice", META)).isZero();
        assertThatCode(() -> limiter.clear("alice", META)).doesNotThrowAnyException();
        assertThatCode(() -> limiter.assertPasswordChangeAllowed(userId)).doesNotThrowAnyException();
        assertThatCode(() -> limiter.recordPasswordChangeFailure(userId)).doesNotThrowAnyException();

        assertThat(fallbacks()).isEqualTo(4);
    }

    @Test
    void lockSecondsConstant_matchesLockTtl() {
        assertThat(LoginRateLimiter.LOCK_SECONDS).isEqualTo(900);
    }
}
