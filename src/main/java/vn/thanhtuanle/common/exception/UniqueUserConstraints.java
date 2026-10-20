package vn.thanhtuanle.common.exception;

import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import vn.thanhtuanle.oj.common.web.error.ErrorCodeSpec;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The unique indexes identity's V6 puts on {@code t_users} (live accounts only), as the conflicts they mean. The
 * service's own checks run first with the same rules; these indexes are the last word, and also settle two writes that
 * race past the checks, and writes that have no check (a Google sign-in's new account).
 */
public final class UniqueUserConstraints {

    private static final Map<String, ErrorCode> CONFLICTS = Map.of(
            "ux_users_username_lower", ErrorCode.USERNAME_EXISTED,
            "ux_users_email_lower", ErrorCode.EMAIL_EXISTED,
            "ux_users_google_id", ErrorCode.GOOGLE_ACCOUNT_EXISTED);

    private UniqueUserConstraints() {
    }

    /**
     * The conflict a violation of one of those indexes means, found by the constraint name Hibernate read from the
     * database's error ({@link ConstraintViolationException#getConstraintName()}) anywhere in the cause chain. Any other
     * violation is not a user conflict: empty.
     */
    public static Optional<ErrorCode> toErrorCode(DataIntegrityViolationException e) {
        for (Throwable cause = e; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof ConstraintViolationException violation) {
                String name = violation.getConstraintName();
                return name == null ? Optional.empty()
                        : Optional.ofNullable(CONFLICTS.get(name.toLowerCase(Locale.ROOT)));
            }
        }
        return Optional.empty();
    }

    /** Whether this code is one of those conflicts. */
    public static boolean isConflict(ErrorCodeSpec code) {
        return CONFLICTS.containsValue(code);
    }
}
