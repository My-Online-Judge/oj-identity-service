package vn.thanhtuanle.user;

import vn.thanhtuanle.entity.User;

import java.util.Optional;
import java.util.UUID;

/** A {@link UserRepository} fragment: the user's row lock that serialises every change to that user's tokens. */
public interface UserRowLock {

    /**
     * Locks the user's row until the transaction ends. Every change to a user's tokens (rotation, reuse detection,
     * logout, login, password change) takes it first, so a delete-all cannot miss a successor that a concurrent
     * rotation is about to commit. Waits at most {@link UserRowLockImpl#LOCK_TIMEOUT} for a holder, then throws
     * {@link UserLockTimeoutException} (503), and the caller's transaction rolls back.
     */
    Optional<User> lockById(UUID id);
}
