package vn.thanhtuanle.user;

import java.text.Normalizer;
import java.util.HexFormat;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.random.RandomGenerator;
import java.util.regex.Pattern;

/**
 * Public handles (usernames) derived from a display name, inside the username rule {@code ^[a-zA-Z0-9_]{3,32}$}.
 * Pure and static: the Google sign-up ({@link HandleAllocator}) and Flyway's V8 backfill pick handles with the same
 * {@link #allocate} ladder, each with its own "is it taken" check.
 */
public final class UserHandles {

    /** A base leaves room for the longest suffix: {@code 28 + "_999"} is the rule's 32. */
    public static final int MAX_BASE = 28;
    public static final int MAX_SUFFIX = 999;

    /** The random fallback keeps this much of the base: {@code 23 + "_" + 8 hex} is 32. */
    private static final int FALLBACK_BASE = 23;
    private static final int MIN_LENGTH = 3;
    /** A name with nothing usable gets {@code user} and this many random hex digits. */
    private static final String ANONYMOUS = "user";
    private static final int ANONYMOUS_HEX = 6;

    private static final Pattern MARKS = Pattern.compile("\\p{M}+");
    private static final Pattern OUTSIDE_RULE = Pattern.compile("[^a-z0-9]+");
    private static final Pattern EDGE_SEPARATORS = Pattern.compile("^_+|_+$");

    private UserHandles() {
    }

    /**
     * The handle a name asks for: lower case, diacritics removed (NFD, combining marks dropped, {@code đ} is
     * {@code d}), each run of anything outside {@code [a-z0-9]} one {@code _}, no {@code _} at either end, at most
     * {@link #MAX_BASE} characters (a {@code _} left at the cut is dropped). Shorter than 3: {@code user_} + it. Empty
     * when nothing usable remains (no name, or only punctuation or other scripts): {@link #allocate} then gives
     * {@code user} + 6 random hex digits.
     */
    public static String base(String source) {
        if (source == null) {
            return "";
        }
        String folded = MARKS.matcher(Normalizer.normalize(source.toLowerCase(Locale.ROOT), Normalizer.Form.NFD))
                .replaceAll("")
                .replace('đ', 'd');
        String handle = trimSeparators(OUTSIDE_RULE.matcher(folded).replaceAll("_"));
        if (handle.length() > MAX_BASE) {
            handle = trimSeparators(handle.substring(0, MAX_BASE));
        }
        if (handle.isEmpty() || handle.length() >= MIN_LENGTH) {
            return handle;
        }
        return ANONYMOUS + "_" + handle;
    }

    /** The n-th handle tried for a base: the base itself, then {@code base_2} ... {@code base_999}. */
    public static String candidate(String base, int n) {
        return n == 1 ? base : base + "_" + n;
    }

    /** When every numbered candidate is taken: the base cut to 23, {@code _}, and 8 random lowercase hex digits. */
    public static String randomFallback(String base, RandomGenerator random) {
        String kept = base.length() > FALLBACK_BASE ? base.substring(0, FALLBACK_BASE) : base;
        return kept + "_" + HexFormat.of().toHexDigits(random.nextInt());
    }

    /** The handle of a name with nothing usable in it: {@code user} and 6 random lowercase hex digits. */
    public static String anonymous(RandomGenerator random) {
        return ANONYMOUS + HexFormat.of().toHexDigits(random.nextInt()).substring(0, ANONYMOUS_HEX);
    }

    /**
     * The first free handle for this name: {@code base}, {@code base_2} ... {@code base_999}, then
     * {@link #randomFallback}. A name with nothing usable tries {@link #anonymous}, then {@code randomFallback("user")}.
     *
     * @param taken whether a live account already has the handle, in any case
     * @throws IllegalStateException when the random fallback is taken too
     */
    public static String allocate(String source, Predicate<String> taken, RandomGenerator random) {
        String base = base(source);
        if (base.isEmpty()) {
            String handle = anonymous(random);
            return taken.test(handle) ? free(randomFallback(ANONYMOUS, random), taken) : handle;
        }
        for (int n = 1; n <= MAX_SUFFIX; n++) {
            String handle = candidate(base, n);
            if (!taken.test(handle)) {
                return handle;
            }
        }
        return free(randomFallback(base, random), taken);
    }

    private static String free(String handle, Predicate<String> taken) {
        if (taken.test(handle)) {
            throw new IllegalStateException("No free handle: even the random fallback is taken");
        }
        return handle;
    }

    private static String trimSeparators(String handle) {
        return EDGE_SEPARATORS.matcher(handle).replaceAll("");
    }
}
