package vn.thanhtuanle.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LoginRateLimiterTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "probe/1.0");

    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> valueOps;

    LoginRateLimiter limiter;

    @BeforeEach
    void setUp() {
        when(redis.opsForValue()).thenReturn(valueOps);
        when(redis.hasKey(anyString())).thenReturn(false);
        limiter = new LoginRateLimiter(redis, new SimpleMeterRegistry());
    }

    @Test
    void allowed_whenNoLockExists() {
        assertThatCode(() -> limiter.assertAllowed("alice", META)).doesNotThrowAnyException();
    }

    @Test
    void blocked_whenUsernameLocked() {
        when(redis.hasKey("oj:rl:lock:username:alice")).thenReturn(true);
        assertThatThrownBy(() -> limiter.assertAllowed("alice", META))
                .isInstanceOf(AppException.class)
                .extracting(e -> ((AppException) e).getErrorCode())
                .isEqualTo(ErrorCode.RATE_LIMITED);
    }

    @Test
    void blocked_whenIpLocked() {
        when(redis.hasKey("oj:rl:lock:ip:1.2.3.4")).thenReturn(true);
        assertThatThrownBy(() -> limiter.assertAllowed("bob", META)).isInstanceOf(AppException.class);
    }

    @Test
    void failure_incrementsAllThreeCounters_andSetsWindowOnFirst() {
        when(valueOps.increment(anyString())).thenReturn(1L);
        limiter.recordFailure("alice", META);
        verify(valueOps).increment("oj:rl:login:username:alice");
        verify(valueOps).increment("oj:rl:login:ip:1.2.3.4");
        verify(valueOps).increment("oj:rl:login:device:dev-1");
        verify(redis).expire(eq("oj:rl:login:username:alice"), eq(Duration.ofMinutes(5)));
    }

    @Test
    void fifthUsernameFailure_locksUsername() {
        when(valueOps.increment(anyString())).thenReturn(5L);
        limiter.recordFailure("alice", META);
        verify(valueOps).set(eq("oj:rl:lock:username:alice"), eq("1"), eq(Duration.ofMinutes(15)));
    }

    @Test
    void fifthFailure_doesNotLockIpOrDevice_thresholdIsTen() {
        when(valueOps.increment(anyString())).thenReturn(5L);
        limiter.recordFailure("alice", META);
        verify(valueOps, never()).set(eq("oj:rl:lock:ip:1.2.3.4"), any(), any(Duration.class));
        verify(valueOps, never()).set(eq("oj:rl:lock:device:dev-1"), any(), any(Duration.class));
    }

    @Test
    void nullDeviceHash_isSkipped() {
        when(valueOps.increment(anyString())).thenReturn(1L);
        limiter.recordFailure("alice", new ClientMeta("1.2.3.4", null, null));
        verify(valueOps, never()).increment("oj:rl:login:device:null");
    }

    @Test
    void clear_deletesTheUsernameCounter() {
        limiter.clear("alice");
        verify(redis).delete("oj:rl:login:username:alice");
    }

    @Test
    void redisDown_failsOpen() {
        when(redis.hasKey(anyString())).thenThrow(new RuntimeException("redis down"));
        assertThatCode(() -> limiter.assertAllowed("alice", META)).doesNotThrowAnyException();
    }

    @Test
    void lockSecondsConstant_matchesLockTtl() {
        assertThat(LoginRateLimiter.LOCK_SECONDS).isEqualTo(900);
    }
}
