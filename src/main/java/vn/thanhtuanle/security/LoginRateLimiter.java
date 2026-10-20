package vn.thanhtuanle.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Redis-backed brute-force lockout for password logins and for the current-password check of a password change.
 *
 * <p>Failed logins are counted per (username, IP) pair and per IP in a 5-minute window, and per account in a 1-hour
 * window ({@code oj:rl:login:*}). Crossing a limit (5 per pair, 30 per IP, 50 per account) parks a lock key
 * ({@code oj:rl:lock:} + the same suffix) for 15 minutes; while one exists, the login answers 429. Locking the pair,
 * not the username, means a spray against alice from one address cannot lock alice out from her own; the account and
 * IP ceilings bound a distributed guess and a single-address spray. From a pair's fourth failure on, each failure also
 * costs a growing delay ({@link #backoff}). A successful login clears its pair's counter.
 *
 * <p>Redis being down fails OPEN (login availability beats enforcement here), and each such call increments
 * {@code oj.redis.fallback{lookup=login}}, which the RedisUnavailable alert watches.
 */
@Component
@Slf4j
public class LoginRateLimiter {

    static final String COUNT_PREFIX = "oj:rl:login:";
    static final String LOCK_PREFIX = "oj:rl:lock:";
    static final Duration WINDOW = Duration.ofMinutes(5);
    static final Duration ACCOUNT_WINDOW = Duration.ofHours(1);
    static final Duration LOCK = Duration.ofMinutes(15);
    static final int PAIR_LIMIT = 5;
    static final int IP_LIMIT = 30;
    static final int ACCOUNT_LIMIT = 50;
    static final int PASSWORD_CHANGE_LIMIT = 5;
    static final Duration MAX_BACKOFF = Duration.ofSeconds(8);
    /** Public for the Retry-After header in GlobalExceptionHandler. */
    public static final long LOCK_SECONDS = LOCK.toSeconds();

    private final StringRedisTemplate redis;
    private final Counter throttled;
    private final Counter fallbacks;

    public LoginRateLimiter(StringRedisTemplate redis, MeterRegistry registry) {
        this.redis = redis;
        // Held for cheap increments; not a guarantee of an always-visible zero series (see the note
        // in SubmissionRateLimiter — alerts are absent-safe rather than relying on pre-registration).
        this.throttled = Counter.builder("oj.login.rate_limited")
                .description("Login attempts rejected while a lockout was in force")
                .register(registry);
        this.fallbacks = Counter.builder("oj.redis.fallback")
                .description("Requests or work that went on without Redis because a Redis call failed (fail-open)")
                .tag("lookup", "login")
                .register(registry);
    }

    /**
     * The delay a failed login costs, given n = the pair's failure count including this one: none for the first three,
     * then 2^(n−3) seconds capped at 8 (4 → 2 s, 5 → 4 s, 6 and later → 8 s).
     */
    static Duration backoff(long n) {
        if (n <= 3) {
            return Duration.ZERO;
        }
        // The exponent is clamped before the shift, so a large n cannot overflow past the cap.
        return Duration.ofSeconds(Math.min(MAX_BACKOFF.toSeconds(), 1L << Math.min(n - 3, 4)));
    }

    /** Throws 429 RATE_LIMITED, with Retry-After = the lock's length, when the pair, the account or the IP is locked. */
    public void assertAllowed(String username, ClientMeta meta) {
        List<String> locks = Stream.of(pair(username, meta.ip()), account(username), ip(meta.ip()))
                .filter(Objects::nonNull)
                .map(suffix -> LOCK_PREFIX + suffix)
                .toList();
        if (locks.isEmpty()) {
            return;
        }
        Long locked;
        try {
            locked = redis.countExistingKeys(locks);
        } catch (Exception e) {
            failOpen("allowing login", e);
            return;
        }
        if (locked != null && locked > 0) {
            throttled.increment();
            throw new RateLimitedException(ErrorCode.RATE_LIMITED, LOCK_SECONDS);
        }
    }

    /** Counts a failed login against its pair, account and IP, locks any that reach its limit, returns the delay. */
    public Duration recordFailure(String username, ClientMeta meta) {
        try {
            long pairFailures = bump(pair(username, meta.ip()), WINDOW, PAIR_LIMIT);
            bump(account(username), ACCOUNT_WINDOW, ACCOUNT_LIMIT);
            bump(ip(meta.ip()), WINDOW, IP_LIMIT);
            return backoff(pairFailures);
        } catch (Exception e) {
            failOpen("failure not counted", e);
            return Duration.ZERO;
        }
    }

    /** A successful login forgives that pair's earlier typos. The account and IP counters keep counting. */
    public void clear(String username, ClientMeta meta) {
        String pair = pair(username, meta.ip());
        if (pair == null) {
            return;
        }
        try {
            redis.delete(COUNT_PREFIX + pair);
        } catch (Exception e) {
            failOpen("counter not cleared", e);
        }
    }

    /** Throws 429 RATE_LIMITED while this user's password changes are locked after too many wrong current passwords. */
    public void assertPasswordChangeAllowed(UUID userId) {
        boolean locked;
        try {
            locked = Boolean.TRUE.equals(redis.hasKey(LOCK_PREFIX + passwordChange(userId)));
        } catch (Exception e) {
            failOpen("allowing password change", e);
            return;
        }
        if (locked) {
            throw new RateLimitedException(ErrorCode.RATE_LIMITED, LOCK_SECONDS);
        }
    }

    /** Counts a wrong current password; the fifth within the window locks password changes for 15 minutes. */
    public void recordPasswordChangeFailure(UUID userId) {
        try {
            bump(passwordChange(userId), WINDOW, PASSWORD_CHANGE_LIMIT);
        } catch (Exception e) {
            failOpen("password change failure not counted", e);
        }
    }

    private void failOpen(String outcome, Exception e) {
        fallbacks.increment();
        log.warn("Rate limiter unavailable, {}: {}", outcome, e.getMessage());
    }

    /** Increments a counter (its window starts at the first failure), locks it at the limit, returns the count. */
    private long bump(String suffix, Duration window, int limit) {
        if (suffix == null) {
            return 0;
        }
        String key = COUNT_PREFIX + suffix;
        Long count = redis.opsForValue().increment(key);
        if (count == null) {
            return 0;
        }
        if (count == 1L) {
            redis.expire(key, window);
        }
        if (count >= limit) {
            redis.opsForValue().set(LOCK_PREFIX + suffix, "1", LOCK);
        }
        return count;
    }

    private static String pair(String username, String ip) {
        return present(username) && present(ip) ? "pair:" + username + "|" + ip : null;
    }

    private static String account(String username) {
        return present(username) ? "account:" + username : null;
    }

    private static String ip(String ip) {
        return present(ip) ? "ip:" + ip : null;
    }

    private static String passwordChange(UUID userId) {
        return "pwchange:" + userId;
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }
}
