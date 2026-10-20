package vn.thanhtuanle.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Redis-backed brute-force lockout for password logins and for the current-password check of a password change.
 *
 * <p>Login attempts are counted per (username, IP) pair and per IP in a 5-minute window, and per account in a 1-hour
 * window ({@code oj:rl:login:*}). An attempt takes its place in all three counters <em>before</em> its password is
 * checked ({@link #reserve}), in one atomic script: when a lock is in force, or a counter is already at its limit
 * (5 per pair, 50 per account, 30 per IP), it is refused with 429 and no password check. So a burst of parallel guesses
 * cannot all pass one look at the locks. A failure keeps its place; the failure that reaches a limit parks a lock key
 * ({@code oj:rl:lock:} + the same suffix) for 15 minutes. A success hands its places back and forgives its pair.
 *
 * <p>Locking the pair, not the username, means a spray against alice from one address cannot lock alice out from her
 * own; the account and IP ceilings bound a distributed guess and a single-address spray. A pair's fourth and fifth
 * failures also cost a delay ({@link #backoff}).
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
    /** The longest a lock lasts; a refusal's Retry-After is what is left of the keys refusing it. */
    public static final long LOCK_SECONDS = LOCK.toSeconds();

    /**
     * KEYS: lock_1, counter_1, lock_2, counter_2, …  ARGV: limit_1, window_ms_1, limit_2, window_ms_2, …
     * Refused (a lock exists, or a counter is at its limit): {0, the longest PTTL among the refusing keys}.
     * Otherwise every counter is incremented (its window starts with its first attempt): {1, count_1, count_2, …}.
     */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> RESERVE = RedisScript.of("""
            local dimensions = #KEYS / 2
            local refused, retry = false, 0
            for i = 1, dimensions do
              local lock, counter = KEYS[2 * i - 1], KEYS[2 * i]
              if redis.call('EXISTS', lock) == 1 then
                refused = true
                retry = math.max(retry, redis.call('PTTL', lock))
              end
              if tonumber(redis.call('GET', counter) or '0') >= tonumber(ARGV[2 * i - 1]) then
                refused = true
                retry = math.max(retry, redis.call('PTTL', counter))
              end
            end
            if refused then
              return {0, retry}
            end
            local result = {1}
            for i = 1, dimensions do
              local count = redis.call('INCR', KEYS[2 * i])
              if count == 1 then
                redis.call('PEXPIRE', KEYS[2 * i], ARGV[2 * i])
              end
              result[i + 1] = count
            end
            return result
            """, List.class);

    /**
     * KEYS[1]: the pair counter, deleted. KEYS[2…]: counters whose place is handed back. A counter that has expired
     * meanwhile is not recreated at -1 (without a TTL it would hand out extra attempts forever).
     */
    private static final RedisScript<Long> RELEASE = RedisScript.of("""
            redis.call('DEL', KEYS[1])
            for i = 2, #KEYS do
              if redis.call('DECR', KEYS[i]) <= 0 then
                redis.call('DEL', KEYS[i])
              end
            end
            return 1
            """, Long.class);

    /**
     * One login attempt's places in the counters, as {@link #reserve} took them: its ordinal in the pair, account and
     * IP windows. 0 for a dimension that was not counted (blank, or Redis was down).
     */
    public record Attempt(String username, String ip, long pairCount, long accountCount, long ipCount) {
    }

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
     * The delay a failed login costs, given n = the pair's attempt count including this one: none for the first three,
     * then 2^(n−3) seconds capped at 8 (4 → 2 s, 5 → 4 s, 6 and later → 8 s).
     */
    static Duration backoff(long n) {
        if (n <= 3) {
            return Duration.ZERO;
        }
        // The exponent is clamped before the shift, so a large n cannot overflow past the cap.
        return Duration.ofSeconds(Math.min(MAX_BACKOFF.toSeconds(), 1L << Math.min(n - 3, 4)));
    }

    /**
     * Takes this attempt's place in the pair, account and IP counters before its password is checked. Throws 429
     * RATE_LIMITED, with Retry-After = what is left of the longest-lived key refusing it, when the pair, the account or
     * the IP is locked or already at its limit.
     */
    @SuppressWarnings("unchecked")
    public Attempt reserve(String username, ClientMeta meta) {
        List<Dimension> dimensions = dimensions(username, meta.ip());
        if (dimensions.isEmpty()) {
            return new Attempt(username, meta.ip(), 0, 0, 0);
        }
        List<String> keys = new ArrayList<>();
        List<String> args = new ArrayList<>();
        for (Dimension d : dimensions) {
            keys.add(LOCK_PREFIX + d.suffix());
            keys.add(COUNT_PREFIX + d.suffix());
            args.add(String.valueOf(d.limit()));
            args.add(String.valueOf(d.window().toMillis()));
        }
        List<Long> result;
        try {
            result = redis.execute(RESERVE, keys, args.toArray());
        } catch (Exception e) {
            failOpen("allowing login", e);
            return new Attempt(username, meta.ip(), 0, 0, 0);
        }
        if (result == null || result.isEmpty()) {
            return new Attempt(username, meta.ip(), 0, 0, 0);
        }
        if (result.get(0) == 0L) {
            throttled.increment();
            throw new RateLimitedException(ErrorCode.RATE_LIMITED, retryAfterSeconds(result.get(1)));
        }
        long pair = 0;
        long account = 0;
        long ip = 0;
        for (int i = 0; i < dimensions.size(); i++) {
            long count = result.get(i + 1);
            switch (dimensions.get(i).kind()) {
                case PAIR -> pair = count;
                case ACCOUNT -> account = count;
                case IP -> ip = count;
            }
        }
        return new Attempt(username, meta.ip(), pair, account, ip);
    }

    /**
     * A failed attempt keeps its places. The one that reached a limit locks that pair, account or IP. Returns the
     * delay: {@link #backoff} of its pair count, or none above the pair limit (such an attempt got past a lock that is
     * in force by now, and delaying it would only hold a worker thread).
     */
    public Duration recordFailure(Attempt attempt) {
        try {
            lockAtLimit(pair(attempt.username(), attempt.ip()), attempt.pairCount(), PAIR_LIMIT);
            lockAtLimit(account(attempt.username()), attempt.accountCount(), ACCOUNT_LIMIT);
            lockAtLimit(ip(attempt.ip()), attempt.ipCount(), IP_LIMIT);
        } catch (Exception e) {
            failOpen("lock not set", e);
        }
        return attempt.pairCount() > PAIR_LIMIT ? Duration.ZERO : backoff(attempt.pairCount());
    }

    /**
     * A success is not a failure: it hands its account and IP places back and forgives its pair's earlier typos (the
     * pair counter is deleted). Earlier failures still count against the account and the IP.
     */
    public void recordSuccess(Attempt attempt) {
        String pair = pair(attempt.username(), attempt.ip());
        if (pair == null) {
            return;
        }
        List<String> keys = new ArrayList<>(3);
        keys.add(COUNT_PREFIX + pair);
        String account = account(attempt.username());
        if (account != null && attempt.accountCount() > 0) {
            keys.add(COUNT_PREFIX + account);
        }
        String ip = ip(attempt.ip());
        if (ip != null && attempt.ipCount() > 0) {
            keys.add(COUNT_PREFIX + ip);
        }
        try {
            redis.execute(RELEASE, keys);
        } catch (Exception e) {
            failOpen("counters not released", e);
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
            String suffix = passwordChange(userId);
            String key = COUNT_PREFIX + suffix;
            Long count = redis.opsForValue().increment(key);
            if (count != null && count == 1L) {
                redis.expire(key, WINDOW);
            }
            if (count != null && count >= PASSWORD_CHANGE_LIMIT) {
                redis.opsForValue().set(LOCK_PREFIX + suffix, "1", LOCK);
            }
        } catch (Exception e) {
            failOpen("password change failure not counted", e);
        }
    }

    private void failOpen(String outcome, Exception e) {
        fallbacks.increment();
        log.warn("Rate limiter unavailable, {}: {}", outcome, e.getMessage());
    }

    private void lockAtLimit(String suffix, long count, int limit) {
        if (suffix != null && count >= limit) {
            redis.opsForValue().set(LOCK_PREFIX + suffix, "1", LOCK);
        }
    }

    /** Whole seconds, rounded up, never below 1: a client told 0 would retry at once. */
    private static long retryAfterSeconds(Long millis) {
        if (millis == null || millis <= 0) {
            return 1;
        }
        return Math.max(1, (millis + 999) / 1000);
    }

    private enum Kind { PAIR, ACCOUNT, IP }

    private record Dimension(Kind kind, String suffix, int limit, Duration window) {
    }

    private static List<Dimension> dimensions(String username, String ip) {
        List<Dimension> dimensions = new ArrayList<>(3);
        String pair = pair(username, ip);
        if (pair != null) {
            dimensions.add(new Dimension(Kind.PAIR, pair, PAIR_LIMIT, WINDOW));
        }
        String account = account(username);
        if (account != null) {
            dimensions.add(new Dimension(Kind.ACCOUNT, account, ACCOUNT_LIMIT, ACCOUNT_WINDOW));
        }
        String address = ip(ip);
        if (address != null) {
            dimensions.add(new Dimension(Kind.IP, address, IP_LIMIT, WINDOW));
        }
        return dimensions;
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
