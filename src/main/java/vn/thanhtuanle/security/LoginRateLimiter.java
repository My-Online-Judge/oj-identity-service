package vn.thanhtuanle.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
 * <p>Login attempts are counted per (username, IP) pair in a 5-minute window and per account in a 1-hour window
 * ({@code oj:rl:login:*}). An attempt takes its place in both counters <em>before</em> its password is checked
 * ({@link #reserve}), in one atomic script, so a burst of parallel guesses cannot all pass one look at the locks:
 * <ul>
 *   <li>a lock in force ({@code oj:rl:lock:} + the same suffix), the IP's included, refuses it with 429 and no
 *       password check;</li>
 *   <li>otherwise it is counted. The one that goes over a limit (5 per pair, 50 per account by default,
 *       {@code oj.login.account-limit}) locks that key in the same step (for {@link #PROBE_LOCK_TTL} 60 s, until its
 *       failure makes it 15 minutes) and is let through as the single probe; everything after it is refused.</li>
 * </ul>
 * A failure keeps its places, and the failure that reaches a limit locks it ({@link #recordFailure}). A success hands
 * its places back, forgives its pair and lifts a lock it set as the probe ({@link #recordSuccess}). So a burst gets at
 * most limit + 1 password checks per key, and after a lock runs out one probe may try again: the right password signs
 * in, a wrong one locks for another 15 minutes.
 *
 * <p>The IP counts failed password checks only (30 in 5 minutes by default, {@code oj.login.ip-limit}): a failure
 * increments it, and the one that reaches the limit locks the address for 15 minutes. Correct logins never count, in
 * flight or after, so a hall behind one NAT address that signs in at once is not refused, and a typo during that burst
 * is one failure among the hall's, not a 15-minute lock for everyone.
 *
 * <p>A lock's value says who set it: {@code probe:<random>} for the probe's, {@code fail:<random>} for a failure's. The
 * probe lifts only a lock that still holds its own value, so a failure still in flight that locked the key again keeps
 * its lock. A refusal answers what is left of a failure's lock, but "retry in 2 s" for a probe's: a probe usually
 * settles within a second.
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
    static final int PASSWORD_CHANGE_LIMIT = 5;
    static final Duration MAX_BACKOFF = Duration.ofSeconds(8);
    /** The Retry-After of a refusal by a probe's lock: the probe is in flight, and usually settles within a second. */
    static final Duration PROBE_RETRY = Duration.ofSeconds(2);
    /** The value prefixes of a lock set by the probe and by a failure (the RESERVE script reads the probe's). */
    static final String PROBE_LOCK = "probe:";
    static final String FAIL_LOCK = "fail:";
    /**
     * How long a probe's lock lasts. It outlives its probe only if identity dies mid-probe (a failed probe overwrites
     * it with a {@link #LOCK 15-minute} failure lock, a settled one deletes it), and clients refused meanwhile are told
     * to retry in {@link #PROBE_RETRY}, so it must not hold the key for 15 minutes.
     */
    static final Duration PROBE_LOCK_TTL = Duration.ofSeconds(60);
    /** A lock's length, so the longest Retry-After: a refusal answers what is left of the locks refusing it. */
    public static final long LOCK_SECONDS = LOCK.toSeconds();

    /**
     * KEYS: lock_1, counter_1, …, lock_n, counter_n for the dimensions an attempt takes a place in (pair, account), then
     * the locks that only refuse (the IP's, whose counter counts failures: {@link #COUNT_FAILURE}). ARGV: limit_1,
     * window_ms_1, …, limit_n, window_ms_n, then this attempt's probe token ({@code probe:<random>}), the probe's retry
     * in ms and its lock's length in ms; so n = (#ARGV - 3) / 2.
     * Refused when any of the locks exists: {0, the longest wait among them}, where a failure's lock (any value not
     * starting with {@code probe:}) waits its PTTL and a probe's the probe retry. Otherwise every counter is incremented
     * (its window starts with its first attempt), and one that goes over its limit locks its key with the probe token
     * for the probe's lock length (a failure sets the long lock): this attempt is the probe.
     * Returns {1, count_1, …, count_n, probe_1, …, probe_n}.
     */
    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> RESERVE = RedisScript.of("""
            local dimensions = (#ARGV - 3) / 2
            local probeToken = ARGV[2 * dimensions + 1]
            local probeRetryMs = tonumber(ARGV[2 * dimensions + 2])
            local probeLockMs = ARGV[2 * dimensions + 3]
            local refused, retry = false, 0
            for i = 1, #KEYS do
              if i > 2 * dimensions or i % 2 == 1 then
                local holder = redis.call('GET', KEYS[i])
                if holder then
                  refused = true
                  if string.sub(holder, 1, 6) == 'probe:' then
                    retry = math.max(retry, probeRetryMs)
                  else
                    retry = math.max(retry, redis.call('PTTL', KEYS[i]))
                  end
                end
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
                redis.call('SET', KEYS[2 * i - 1], probeToken, 'PX', probeLockMs)
                result[1 + dimensions + i] = 1
              end
            end
            return result
            """, List.class);

    /**
     * KEYS[1]: a failure counter, KEYS[2]: its lock. ARGV: the limit, the window in ms, the failure's lock value and the
     * lock's length in ms. Counts one failure (the window starts with the first) and locks at the limit. Returns the
     * count.
     */
    private static final RedisScript<Long> COUNT_FAILURE = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
              redis.call('PEXPIRE', KEYS[1], ARGV[2])
            end
            if count >= tonumber(ARGV[1]) then
              redis.call('SET', KEYS[2], ARGV[3], 'PX', ARGV[4])
            end
            return count
            """, Long.class);

    /**
     * KEYS: the counters an attempt hands back, then the locks it set as the probe. ARGV[1]: how many of KEYS are
     * counters. ARGV[2]: '1' when the first counter is the pair's and is deleted (a success forgives its typos);
     * otherwise every counter gives back one place. ARGV[3]: the attempt's probe token; a lock is deleted only while it
     * still holds it (a failure may have locked the key again meanwhile). A counter that has expired meanwhile is not
     * recreated at -1 (without a TTL it would hand out extra attempts forever).
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
              if redis.call('GET', KEYS[i]) == ARGV[3] then
                redis.call('DEL', KEYS[i])
              end
            end
            return 1
            """, Long.class);

    /**
     * One login attempt's places in the counters, as {@link #reserve} took them: its ordinal in the pair and account
     * windows (0 for a dimension that was not counted: blank, or Redis was down), for each whether this attempt went
     * over the limit and locked it, i.e. is that key's probe, and the value it wrote into those locks ({@code null}
     * when it is no key's probe). It takes no place in the IP's counter, which counts failures only.
     */
    public record Attempt(String username, String ip, long pairCount, long accountCount,
                          boolean pairProbe, boolean accountProbe, String probeToken) {

        /** An attempt that is no key's probe. */
        public Attempt(String username, String ip, long pairCount, long accountCount) {
            this(username, ip, pairCount, accountCount, false, false, null);
        }
    }

    /**
     * One password change's place in its counter, as {@link #reservePasswordChange} took it: its ordinal in the window
     * (0 when it was not counted: Redis was down), whether it went over the limit and locked it (the probe), and the
     * value it wrote into that lock ({@code null} when it is not the probe).
     */
    public record PasswordChangeAttempt(UUID userId, long count, boolean probe, String probeToken) {
    }

    private final StringRedisTemplate redis;
    private final Counter throttled;
    private final Counter fallbacks;
    /** Failed password checks from one address in {@link #WINDOW} that lock it ({@code oj.login.ip-limit}). */
    private final int ipLimit;
    /** Attempts on one account in {@link #ACCOUNT_WINDOW} past which it locks ({@code oj.login.account-limit}). */
    private final int accountLimit;

    public LoginRateLimiter(StringRedisTemplate redis, MeterRegistry registry,
                            @Value("${oj.login.ip-limit:30}") int ipLimit,
                            @Value("${oj.login.account-limit:50}") int accountLimit) {
        // A limit of 0 would lock every first failure (IP) or refuse every login (account): a typo, never a policy.
        requireAtLeastOne("oj.login.ip-limit (OJ_LOGIN_IP_LIMIT)", ipLimit);
        requireAtLeastOne("oj.login.account-limit (OJ_LOGIN_ACCOUNT_LIMIT)", accountLimit);
        this.redis = redis;
        this.ipLimit = ipLimit;
        this.accountLimit = accountLimit;
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

    private static void requireAtLeastOne(String setting, int value) {
        if (value < 1) {
            throw new IllegalStateException(setting + " must be at least 1, was " + value);
        }
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
     * Takes this attempt's place in the pair and account counters before its password is checked. Throws 429
     * RATE_LIMITED when the pair, the account or the IP is locked, with Retry-After = the longest wait among the locks
     * refusing it: what is left of a failure's lock (at most 15 minutes), 2 s for a probe's. An attempt that goes over
     * a limit locks that key and is its probe.
     */
    @SuppressWarnings("unchecked")
    public Attempt reserve(String username, ClientMeta meta) {
        List<Dimension> dimensions = dimensions(username, meta.ip());
        String address = ip(meta.ip());
        if (dimensions.isEmpty() && address == null) {
            return new Attempt(username, meta.ip(), 0, 0);
        }
        List<String> keys = new ArrayList<>();
        List<String> args = new ArrayList<>();
        for (Dimension d : dimensions) {
            keys.add(LOCK_PREFIX + d.suffix());
            keys.add(COUNT_PREFIX + d.suffix());
            args.add(String.valueOf(d.limit()));
            args.add(String.valueOf(d.window().toMillis()));
        }
        if (address != null) {
            keys.add(LOCK_PREFIX + address);
        }
        String probeToken = PROBE_LOCK + UUID.randomUUID();
        args.add(probeToken);
        args.add(String.valueOf(PROBE_RETRY.toMillis()));
        args.add(String.valueOf(PROBE_LOCK_TTL.toMillis()));
        List<Long> result;
        try {
            result = redis.execute(RESERVE, keys, args.toArray());
        } catch (Exception e) {
            failOpen("allowing login", e);
            return new Attempt(username, meta.ip(), 0, 0);
        }
        if (result == null || result.isEmpty()) {
            return new Attempt(username, meta.ip(), 0, 0);
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
        boolean probe = probes[Kind.PAIR.ordinal()] || probes[Kind.ACCOUNT.ordinal()];
        return new Attempt(username, meta.ip(), counts[Kind.PAIR.ordinal()], counts[Kind.ACCOUNT.ordinal()],
                probes[Kind.PAIR.ordinal()], probes[Kind.ACCOUNT.ordinal()], probe ? probeToken : null);
    }

    /**
     * A failed attempt keeps its places, and a lock it set as the probe stays. The one that reached a limit locks that
     * pair or account. The failure is counted for its IP, and the one that reaches the IP limit locks the address.
     * Returns the delay: {@link #backoff} of its pair count, or none above the pair limit (such an attempt is a probe,
     * or got past a lock that is in force by now: delaying it would only hold a worker thread).
     */
    public Duration recordFailure(Attempt attempt) {
        String failToken = FAIL_LOCK + UUID.randomUUID();
        try {
            lockAtLimit(pair(attempt.username(), attempt.ip()), attempt.pairCount(), PAIR_LIMIT, failToken);
            lockAtLimit(account(attempt.username()), attempt.accountCount(), accountLimit, failToken);
            String address = ip(attempt.ip());
            if (address != null) {
                countFailure(address, ipLimit, failToken);
            }
        } catch (Exception e) {
            failOpen("lock not set", e);
        }
        return attempt.pairCount() > PAIR_LIMIT ? Duration.ZERO : backoff(attempt.pairCount());
    }

    /**
     * A success is not a failure: it hands its account place back, forgives its pair's earlier typos (the pair counter
     * is deleted) and lifts any lock it set as the probe. Earlier failures still count against the account and the IP.
     * A lock that a failure set again meanwhile stays.
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
        List<String> counters = new ArrayList<>(2);
        boolean deletePair = success && pair != null;
        if (pair != null && (success || attempt.pairCount() > 0)) {
            counters.add(COUNT_PREFIX + pair);
        }
        if (account != null && attempt.accountCount() > 0) {
            counters.add(COUNT_PREFIX + account);
        }
        List<String> keys = new ArrayList<>(counters);
        String probeToken = attempt.probeToken();
        if (probeToken != null) {
            if (attempt.pairProbe() && pair != null) {
                keys.add(LOCK_PREFIX + pair);
            }
            if (attempt.accountProbe() && account != null) {
                keys.add(LOCK_PREFIX + account);
            }
        }
        if (keys.isEmpty()) {
            return;
        }
        try {
            redis.execute(RELEASE, keys, String.valueOf(counters.size()), deletePair ? "1" : "0",
                    probeToken == null ? "" : probeToken);
        } catch (Exception e) {
            failOpen("counters not released", e);
        }
    }

    /**
     * Takes this password change's place in its counter ({@code pwchange:<uid>}, {@link #PASSWORD_CHANGE_LIMIT} per
     * {@link #WINDOW}) before the current password is checked, with the login's script and one dimension: a burst of
     * wrong current passwords gets at most the limit and one probe BCrypt checks. Throws 429
     * PASSWORD_CHANGE_RATE_LIMITED while the key is locked, with Retry-After = what is left of a failure's lock, 2 s for
     * a probe's. Redis down: fails open, uncounted.
     */
    @SuppressWarnings("unchecked")
    public PasswordChangeAttempt reservePasswordChange(UUID userId) {
        String suffix = passwordChange(userId);
        String probeToken = PROBE_LOCK + UUID.randomUUID();
        List<Long> result;
        try {
            result = redis.execute(RESERVE, List.of(LOCK_PREFIX + suffix, COUNT_PREFIX + suffix),
                    String.valueOf(PASSWORD_CHANGE_LIMIT), String.valueOf(WINDOW.toMillis()), probeToken,
                    String.valueOf(PROBE_RETRY.toMillis()), String.valueOf(PROBE_LOCK_TTL.toMillis()));
        } catch (Exception e) {
            failOpen("allowing password change", e);
            return new PasswordChangeAttempt(userId, 0, false, null);
        }
        if (result == null || result.isEmpty()) {
            return new PasswordChangeAttempt(userId, 0, false, null);
        }
        if (result.get(0) == 0L) {
            throw new RateLimitedException(ErrorCode.PASSWORD_CHANGE_RATE_LIMITED, retryAfterSeconds(result.get(1)));
        }
        boolean probe = result.size() > 2 && result.get(2) == 1L;
        return new PasswordChangeAttempt(userId, result.get(1), probe, probe ? probeToken : null);
    }

    /**
     * A wrong current password keeps its place; the one whose place reached the limit locks password changes for
     * {@link #LOCK 15 minutes} (overwriting a probe's lock).
     */
    public void recordPasswordChangeFailure(PasswordChangeAttempt attempt) {
        try {
            lockAtLimit(passwordChange(attempt.userId()), attempt.count(), PASSWORD_CHANGE_LIMIT,
                    FAIL_LOCK + UUID.randomUUID());
        } catch (Exception e) {
            failOpen("password change lock not set", e);
        }
    }

    /**
     * Any other outcome (a success, an unchanged or invalid new password, an exception) hands the place back and lifts
     * a lock the attempt set as the probe. The counter itself is never deleted: earlier failures still count.
     */
    public void releasePasswordChange(PasswordChangeAttempt attempt) {
        String suffix = passwordChange(attempt.userId());
        List<String> keys = new ArrayList<>(2);
        if (attempt.count() > 0) {
            keys.add(COUNT_PREFIX + suffix);
        }
        int counters = keys.size();
        if (attempt.probe() && attempt.probeToken() != null) {
            keys.add(LOCK_PREFIX + suffix);
        }
        if (keys.isEmpty()) {
            return;
        }
        try {
            redis.execute(RELEASE, keys, String.valueOf(counters), "0",
                    attempt.probeToken() == null ? "" : attempt.probeToken());
        } catch (Exception e) {
            failOpen("password change place not released", e);
        }
    }

    private void failOpen(String outcome, Exception e) {
        fallbacks.increment();
        log.warn("Rate limiter unavailable, {}: {}", outcome, e.getMessage());
    }

    private void lockAtLimit(String suffix, long count, int limit, String failToken) {
        if (suffix != null && count >= limit) {
            redis.opsForValue().set(LOCK_PREFIX + suffix, failToken, LOCK);
        }
    }

    /** Counts one failure for this key in a {@link #WINDOW}; the one that reaches the limit locks the key. */
    private void countFailure(String suffix, int limit, String failToken) {
        redis.execute(COUNT_FAILURE, List.of(COUNT_PREFIX + suffix, LOCK_PREFIX + suffix), String.valueOf(limit),
                String.valueOf(WINDOW.toMillis()), failToken, String.valueOf(LOCK.toMillis()));
    }

    /** Whole seconds, rounded up, never below 1: a client told 0 would retry at once. */
    private static long retryAfterSeconds(Long millis) {
        if (millis == null || millis <= 0) {
            return 1;
        }
        return Math.max(1, (millis + 999) / 1000);
    }

    private enum Kind { PAIR, ACCOUNT }

    private record Dimension(Kind kind, String suffix, int limit, Duration window) {
    }

    /** The dimensions an attempt takes a place in before its password is checked (not the IP: it counts failures). */
    private List<Dimension> dimensions(String username, String ip) {
        List<Dimension> dimensions = new ArrayList<>(2);
        String pair = pair(username, ip);
        if (pair != null) {
            dimensions.add(new Dimension(Kind.PAIR, pair, PAIR_LIMIT, WINDOW));
        }
        String account = account(username);
        if (account != null) {
            dimensions.add(new Dimension(Kind.ACCOUNT, account, accountLimit, ACCOUNT_WINDOW));
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
