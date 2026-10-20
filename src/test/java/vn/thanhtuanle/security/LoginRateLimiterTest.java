package vn.thanhtuanle.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.security.LoginRateLimiter.Attempt;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The limiter's own logic with Redis mocked; the scripts, key formats and TTLs are pinned by LoginRateLimiterRedisTest. */
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
        limiter = new LoginRateLimiter(redis, registry);
    }

    private double fallbacks() {
        return registry.counter("oj.redis.fallback", "lookup", "login").count();
    }

    @SuppressWarnings("unchecked")
    private void scriptAnswers(List<Long> result) {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenReturn(result);
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
    void aFailureIsDelayedByItsPairCount_notByTheAccountOrIp() {
        assertThat(limiter.recordFailure(new Attempt("alice", "1.2.3.4", 4, 40, 20))).isEqualTo(Duration.ofSeconds(2));
        assertThat(limiter.recordFailure(new Attempt("alice", "1.2.3.4", 5, 1, 1))).isEqualTo(Duration.ofSeconds(4));
    }

    @Test
    void aFailurePastThePairLimitIsAnsweredAtOnce() {
        // It got past a lock that is in force by now: delaying it would only hold a worker thread.
        assertThat(limiter.recordFailure(new Attempt("alice", "1.2.3.4", 6, 6, 6))).isZero();
        assertThat(limiter.recordFailure(new Attempt("alice", "1.2.3.4", 200, 200, 200))).isZero();
    }

    @Test
    void theFailureThatReachesALimitLocksIt() {
        limiter.recordFailure(new Attempt("alice", "1.2.3.4", 5, 50, 29));

        // A failure's lock is told apart from a probe's, so a probe that succeeds later cannot lift it.
        verify(valueOps).set(eq("oj:rl:lock:pair:alice|1.2.3.4"), startsWith("fail:"), eq(Duration.ofMinutes(15)));
        verify(valueOps).set(eq("oj:rl:lock:account:alice"), startsWith("fail:"), eq(Duration.ofMinutes(15)));
        verify(valueOps, never()).set(org.mockito.ArgumentMatchers.eq("oj:rl:lock:ip:1.2.3.4"), anyString(),
                any(Duration.class));
    }

    @Test
    void aReservationReturnsTheCountsOfThisAttempt() {
        scriptAnswers(List.of(1L, 3L, 12L, 7L, 0L, 0L, 0L));

        Attempt attempt = limiter.reserve("alice", META);

        assertThat(attempt).isEqualTo(new Attempt("alice", "1.2.3.4", 3, 12, 7));
    }

    @Test
    void aReservationThatWentOverALimitIsItsProbe_andKnowsItsLock() {
        scriptAnswers(List.of(1L, 6L, 12L, 7L, 1L, 0L, 0L));

        Attempt attempt = limiter.reserve("alice", META);

        assertThat(attempt.pairCount()).isEqualTo(6);
        assertThat(attempt.accountCount()).isEqualTo(12);
        assertThat(attempt.ipCount()).isEqualTo(7);
        assertThat(attempt.pairProbe()).isTrue();
        assertThat(attempt.accountProbe()).isFalse();
        assertThat(attempt.ipProbe()).isFalse();
        // The value the script wrote into the lock it set, so its success or release lifts that lock only.
        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(redis).execute(any(RedisScript.class), anyList(), args.capture());
        assertThat(attempt.probeToken()).startsWith("probe:").isIn(args.getValue());
    }

    @Test
    void probeTokensAreUnique() {
        scriptAnswers(List.of(1L, 6L, 12L, 7L, 1L, 0L, 0L));

        assertThat(limiter.reserve("alice", META).probeToken()).isNotEqualTo(limiter.reserve("alice", META).probeToken());
    }

    @Test
    void aRefusedReservationIs429WithTheTimeLeft() {
        scriptAnswers(List.of(0L, 29_001L));

        // A RateLimitedException, so the shared handler answers 429 with this Retry-After.
        assertThatThrownBy(() -> limiter.reserve("alice", META))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.getRetryAfterSeconds()).isEqualTo(30);
                });
        assertThat(registry.counter("oj.login.rate_limited").count()).isEqualTo(1);
    }

    @Test
    void redisDown_failsOpen() {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class)))
                .thenThrow(new RedisConnectionFailureException("redis down"));

        assertThatCode(() -> limiter.reserve("alice", META)).doesNotThrowAnyException();
        // Counted, so the RedisUnavailable alert covers identity like the gateway and submission.
        assertThat(fallbacks()).isEqualTo(1);
    }

    @Test
    void redisDown_everyCallFailsOpen_withNoDelay_andIsCounted() {
        RedisConnectionFailureException down = new RedisConnectionFailureException("redis down");
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenThrow(down);
        when(valueOps.increment(anyString())).thenThrow(down);
        org.mockito.Mockito.doThrow(down).when(valueOps).set(anyString(), anyString(), any(Duration.class));
        when(redis.getExpire(anyString(), any())).thenThrow(down);
        when(redis.hasKey(any())).thenThrow(down);
        UUID userId = UUID.randomUUID();

        Attempt unreserved = limiter.reserve("alice", META);
        assertThat(unreserved.pairCount()).isZero();
        assertThat(limiter.recordFailure(new Attempt("alice", "1.2.3.4", 5, 1, 1))).isEqualTo(Duration.ofSeconds(4));
        assertThatCode(() -> limiter.recordSuccess(new Attempt("alice", "1.2.3.4", 1, 1, 1)))
                .doesNotThrowAnyException();
        assertThatCode(() -> limiter.release(new Attempt("alice", "1.2.3.4", 1, 1, 1)))
                .doesNotThrowAnyException();
        assertThatCode(() -> limiter.assertPasswordChangeAllowed(userId)).doesNotThrowAnyException();
        assertThatCode(() -> limiter.recordPasswordChangeFailure(userId)).doesNotThrowAnyException();

        assertThat(fallbacks()).isEqualTo(6);
    }

    @Test
    void lockSecondsConstant_matchesLockTtl() {
        assertThat(LoginRateLimiter.LOCK_SECONDS).isEqualTo(900);
    }
}
