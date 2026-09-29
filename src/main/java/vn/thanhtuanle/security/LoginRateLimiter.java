package vn.thanhtuanle.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;

import java.time.Duration;

/**
 * Redis-backed login brute-force lockout, modeled on the TokenBlocklist idiom.
 *
 * <p>Counts FAILED logins per username / ip / device_hash in a 5-minute window
 * (oj:rl:login:*). Crossing a threshold (5/username, 10/ip, 10/device) parks a lock key
 * (oj:rl:lock:*) with a 15-minute TTL; while it exists, logins for that key answer 429.
 * A successful login clears the username counter. Redis being down fails OPEN — login
 * availability beats enforcement here.
 */
@Component
@Slf4j
public class LoginRateLimiter {

    static final String COUNT_PREFIX = "oj:rl:login:";
    static final String LOCK_PREFIX = "oj:rl:lock:";
    static final Duration WINDOW = Duration.ofMinutes(5);
    static final Duration LOCK = Duration.ofMinutes(15);
    static final int USERNAME_LIMIT = 5;
    static final int IP_LIMIT = 10;
    static final int DEVICE_LIMIT = 10;
    /** Public for the Retry-After header in GlobalExceptionHandler. */
    public static final long LOCK_SECONDS = LOCK.toSeconds();

    private final StringRedisTemplate redis;
    private final Counter throttled;

    public LoginRateLimiter(StringRedisTemplate redis, MeterRegistry registry) {
        this.redis = redis;
        // Held for cheap increments; not a guarantee of an always-visible zero series (see the note
        // in SubmissionRateLimiter — alerts are absent-safe rather than relying on pre-registration).
        this.throttled = Counter.builder("oj.login.rate_limited")
                .description("Login attempts rejected while a lockout was in force")
                .register(registry);
    }

    /** Throws 429 RATE_LIMITED when any dimension of this attempt is locked. */
    public void assertAllowed(String username, ClientMeta meta) {
        boolean locked;
        try {
            locked = isLocked("username", username) || isLocked("ip", meta.ip()) || isLocked("device", meta.deviceHash());
        } catch (Exception e) {
            log.warn("Rate limiter unavailable, allowing login: {}", e.getMessage());
            return;
        }
        if (locked) {
            throttled.increment();
            throw new AppException(ErrorCode.RATE_LIMITED);
        }
    }

    /** Bump all three failure counters; lock any dimension that crosses its threshold. */
    public void recordFailure(String username, ClientMeta meta) {
        try {
            bump("username", username, USERNAME_LIMIT);
            bump("ip", meta.ip(), IP_LIMIT);
            bump("device", meta.deviceHash(), DEVICE_LIMIT);
        } catch (Exception e) {
            log.warn("Rate limiter unavailable, failure not counted: {}", e.getMessage());
        }
    }

    /** A successful login forgives that username's earlier typos. ip/device keep counting. */
    public void clear(String username) {
        try {
            redis.delete(COUNT_PREFIX + "username:" + username);
        } catch (Exception e) {
            log.warn("Rate limiter unavailable, counter not cleared: {}", e.getMessage());
        }
    }

    private boolean isLocked(String dimension, String value) {
        return value != null && !value.isBlank()
                && Boolean.TRUE.equals(redis.hasKey(LOCK_PREFIX + dimension + ":" + value));
    }

    private void bump(String dimension, String value, int limit) {
        if (value == null || value.isBlank()) {
            return;
        }
        String key = COUNT_PREFIX + dimension + ":" + value;
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redis.expire(key, WINDOW);
        }
        if (count != null && count >= limit) {
            redis.opsForValue().set(LOCK_PREFIX + dimension + ":" + value, "1", LOCK);
        }
    }
}
