package vn.thanhtuanle.user;

import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.error.AppException;

/**
 * The user's row stayed locked past the lock timeout: 503 ACCOUNT_BUSY. Its own class so a transaction that keeps
 * other AppExceptions ({@code dontRollbackOn}) can still roll back on it: the failed lock has already aborted the
 * transaction in Postgres, and Hibernate has marked it rollback-only.
 */
public class UserLockTimeoutException extends AppException {

    public UserLockTimeoutException(Throwable cause) {
        super(ErrorCode.ACCOUNT_BUSY);
        initCause(cause);
    }
}
