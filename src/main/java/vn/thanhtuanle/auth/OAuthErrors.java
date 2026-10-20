package vn.thanhtuanle.auth;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** OAuth {@code error} values as they may reach the plain-text log: never more than an error code's shape. */
final class OAuthErrors {

    private static final Pattern LEADING_CODE = Pattern.compile("^[a-z_]{0,32}");

    private OAuthErrors() {
    }

    /**
     * The leading run of {@code [a-z_]}, at most 32 characters, of a value someone else chose ({@code access_denied},
     * {@code invalid_grant}). Anything after it, a line break that would forge a log line included, is dropped.
     */
    static String loggable(String raw) {
        if (raw == null) {
            return null;
        }
        Matcher code = LEADING_CODE.matcher(raw);
        return code.find() ? code.group() : "";
    }
}
