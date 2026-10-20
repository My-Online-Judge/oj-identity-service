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
import java.util.concurrent.TimeUnit;

/**
 * Redis-backed brute-force lockout for password logins and for the current-password check of a password change.
 *
 * <p>Login attempts are counted per (username, IP) pair and per IP in a 5-minute window, and per account in a 1-hour
 * window ({@code oj:rl:login:*}). An attempt takes its place in all three counters <em>before</em> its password is
 * checked ({@link #reserve}), in one atomic script, so a burst of parallel guesses cannot all pass one look at the
 * locks:
 * <ul>
 *   <li>a lock in force ({@code oj:rl:lock:} + the same suffix) refuses it with 429 and no password check;</li>
 *   <li>otherwise it is counted. The one that goes over a limit (5 per pair, 50 per account, 30 per IP) locks that key
 *       for 15 minutes in the same step and is let through as the single probe; everything after it is refused.</li>
 * </ul>
 * A failure keeps its places, and the failure that reaches a limit locks it ({@link #recordFailure}). A success hands
 * its places back, forgives its pair and lifts a lock it set as the probe ({@link #recordSuccess}). So a burst gets at
 * most limit + 1 password checks per key, and after a lock runs out one probe may try again: the right password signs
 * in, a wrong one locks for another 15 minutes.
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
    /** A lock's length, so the longest Retry-After: a refusal answers what is left of the locks refusing it. */
    public static final long LOCK_SECONDS = LOCK.toSeconds();

    /**
     * KEYS: lock_1, counter_1, lock_2, counter_2, …  ARGV: limit_1, window_ms_1, limit_2, window_ms_2, …, lock_ms.
     * Refused when a lock exists: {0, the longest PTTL among them}. Otherwise every counter is incremented (its window
     * starts with its first attempt), and one that goes over its limit locks its key: this attempt is the probe.
     * Returns {1, count_1, …, count_n, probe_1, …, probe_n}.
     */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> RESERVE = RedisScript.of("""
            local dimensions = #KEYS / 2
            local refused, retry = false, 0
            for i = 1, dimensions do
              local lock = KEYS[2 * i - 1]
              if redis.call('EXISTS', lock) == 1 then
                refused = true
                retry = math.max(retry, redis.call('PTTL', lock))
              end
            end
            if refused then
              return {0, retry}
            end
            local result = {1}
            for i = 1, dimensions do
              local counter = KEYS[2 * i]
              local count = redis.call('INCR', counter)
              if count == 1 then
                redis.call('PEXPIRE', counter, ARGV[2 * i])
              end
              result[1 + i] = count
              result[1 + dimensions + i] = 0
              if count > tonumber(ARGV[2 * i - 1]) then
                redis.call('SET', KEYS[2 * i - 1], '1', 'PX', ARGV[#ARGV])
                result[1 + dimensions + i] = 1
              end
            end
            return result
            """, List.class);

    /**
     * KEYS: the counters an attempt hands back, then the locks it set as the probe (deleted). ARGV[1]: how many of KEYS
     * are counters. ARGV[2]: '1' when the first counter is the pair's and is deleted (a success forgives its typos);
     * otherwise every counter gives back one place. A counter that has expired meanwhile is not recreated at -1
     * (without a TTL it would hand out extra attempts forever).
     */
    private static final RedisScript<Long> RELEASE = RedisScript.of("""
            local counters = tonumber(ARGV[1])
            for i = 1, counters do
              if i == 1 and ARGV[2] == '1' then
                redis.call('DEL', KEYS[i])
              elseif redis.call('DECR', KEYS[i]) <= 0 then
                redis.call('DEL', KEYS[i])
              end
            end
            for i = counters + 1, #KEYS do
              redis.call('DEL', KEYS[i])
            end
            return 1
            """, Long.class);

    /**
     * One login attempt's places in the counters, as {@link #reserve} took them: its ordinal in the pair, account and IP
     * windows (0 for a dimension that was not counted: blank, or Redis was down), and for each whether this attempt
     * went over the limit and locked it, i.e. is that key's probe.
     */
    public record Attempt(String username, String ip, long pairCount, long accountCount, long ipCount,
                          boolean pairProbe, boolean accountProbe, boolean ipProbe) {

        /** An attempt that is no key's probe. */
        public Attempt(String username, String ip, long pairCount, long accountCount, long ipCount) {
            this(username, ip, pairCount, accountCount, ipCount, false, false, false);
        }
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
     * RATE_LIMITED, with Retry-After = what is left of the longest of the locks refusing it (at most 15 minutes), when
     * the pair, the account or the IP is locked. An attempt that goes over a limit locks that key and is its probe.
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
        args.add(String.valueOf(LOCK.toMillis()));
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
        long[] counts = new long[Kind.values().length];
        boolean[] probes = new boolean[Kind.values().length];
        int n = dimensions.size();
        for (int i = 0; i < n; i++) {
            int kind = dimensions.get(i).kind().ordinal();
            counts[kind] = result.get(1 + i);
            probes[kind] = result.size() > 1 + n + i && result.get(1 + n + i) == 1L;
        }
        return new Attempt(username, meta.ip(), counts[Kind.PAIR.ordinal()], counts[Kind.ACCOUNT.ordinal()],
                counts[Kind.IP.ordinal()], probes[Kind.PAIR.ordinal()], probes[Kind.ACCOUNT.ordinal()],
                probes[Kind.IP.ordinal()]);
    }

    /**
     * A failed attempt keeps its places, and a lock it set as the probe stays. The one that reached a limit locks that
     * pair, account or IP. Returns the delay: {@link #backoff} of its pair count, or none above the pair limit (such an
     * attempt is a probe, or got past a lock that is in force by now: delaying it would only hold a worker thread).
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
     * A success is not a failure: it hands its account and IP places back, forgives its pair's earlier typos (the pair
     * counter is deleted) and lifts any lock it set as the probe. Earlier failures still count against the account and
     * the IP.
     */
    public void recordSuccess(Attempt attempt) {
        settle(attempt, true);
    }

    /**
     * An attempt that ended without a verdict on its password (the account was busy, or something broke): it hands
     * every place back, the pair's included (no typo is forgiven), and lifts any lock it set as the probe.
     */
    public void release(Attempt attempt) {
        settle(attempt, false);
    }

    private void settle(Attempt attempt, boolean success) {
        String pair = pair(attempt.username(), attempt.ip());
        String account = account(attempt.username());
        String ip = ip(attempt.ip());
        List<String> counters = new ArrayList<>(3);
        boolean deletePair = success && pair != null;
        if (pair != null && (success || attempt.pairCount() > 0)) {
            counters.add(COUNT_PREFIX + pair);
        }
        if (account != null && attempt.accountCount() > 0) {
            counters.add(COUNT_PREFIX + account);
        }
        if (ip != null && attempt.ipCount() > 0) {
            counters.add(COUNT_PREFIX + ip);
        }
        List<String> keys = new ArrayList<>(counters);
        if (attempt.pairProbe() && pair != null) {
            keys.add(LOCK_PREFIX + pair);
        }
        if (attempt.accountProbe() && account != null) {
            keys.add(LOCK_PREFIX + account);
        }
        if (attempt.ipProbe() && ip != null) {
            keys.add(LOCK_PREFIX + ip);
        }
        if (keys.isEmpty()) {
            return;
        }
        try {
            redis.execute(RELEASE, keys, String.valueOf(counters.size()), deletePair ? "1" : "0");
        } catch (Exception e) {
            failOpen("counters not released", e);
        }
    }

    /**
     * Throws 429 PASSWORD_CHANGE_RATE_LIMITED, with Retry-After = what is left of the lock, while this user's password
     * changes are locked after too many wrong current passwords.
     */
    public void assertPasswordChangeAllowed(UUID userId) {
        Long millisLeft;
        try {
            millisLeft = redis.getExpire(LOCK_PREFIX + passwordChange(userId), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            failOpen("allowing password change", e);
            return;
        }
        // PTTL: -2 when there is no lock, -1 for one without a TTL (never written so).
        if (millisLeft != null && millisLeft != -2) {
            throw new RateLimitedException(ErrorCode.PASSWORD_CHANGE_RATE_LIMITED, retryAfterSeconds(millisLeft));
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
