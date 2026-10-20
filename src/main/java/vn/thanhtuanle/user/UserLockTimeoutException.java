package vn.thanhtuanle.user;

import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;

/**
 * The user's row stayed locked past the lock timeout: 503 ACCOUNT_BUSY with {@code Retry-After: 5}, about one lock
 * timeout (the shared handler answers a RateLimitedException with its status and Retry-After). Its own class so a
 * transaction that keeps other AppExceptions ({@code dontRollbackOn}) can still roll back on it: the failed lock has
 * already aborted the transaction in Postgres, and Hibernate has marked it rollback-only.
 */
public class UserLockTimeoutException extends RateLimitedException {

    /** What "try again in a moment" means: about one lock timeout. */
    public static final long RETRY_AFTER_SECONDS = 5;

    public UserLockTimeoutException(Throwable cause) {
        super(ErrorCode.ACCOUNT_BUSY, RETRY_AFTER_SECONDS);
        initCause(cause);
    }
}
