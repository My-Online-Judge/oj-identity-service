package vn.thanhtuanle.user;

import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import jakarta.persistence.LockModeType;
import jakarta.persistence.LockTimeoutException;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.PessimisticLockException;
import org.hibernate.dialect.PostgreSQLDialect;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import vn.thanhtuanle.entity.User;

import java.util.Optional;
import java.util.UUID;

/**
 * The lock behind {@link UserRowLock#lockById}: {@code SELECT … FOR UPDATE} with a 5 s lock timeout.
 *
 * <p>The timeout is {@code SET LOCAL lock_timeout} in the caller's transaction (it then bounds that transaction's later
 * lock waits too, and ends with it), and it runs before any pending write of the transaction is flushed, so that write's
 * row wait is bounded too. The JPA hint {@code jakarta.persistence.lock.timeout} is not enough: Hibernate 6.6's
 * PostgreSQL dialect ignores a positive timeout, and a test showed the lock waiting past 10 s with it. H2 (the test
 * profile) has no such statement and is left alone.
 */
class UserRowLockImpl implements UserRowLock {

    static final String LOCK_TIMEOUT = "5s";

    @PersistenceContext
    private EntityManager entityManager;

    private volatile Boolean postgres;

    @Override
    public Optional<User> lockById(UUID id) {
        if (isPostgres()) {
            // Not flushed first (a native query in AUTO mode flushes the whole session): a pending write of this
            // user, such as a password change's UPDATE, would meet a held row before the timeout is set and wait
            // without limit. The locking select below flushes it, under the timeout.
            entityManager.createNativeQuery("set local lock_timeout = '" + LOCK_TIMEOUT + "'")
                    .setFlushMode(FlushModeType.COMMIT)
                    .executeUpdate();
        }
        try {
            return entityManager.createQuery("select u from User u where u.id = :id", User.class)
                    .setParameter("id", id)
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList()
                    .stream()
                    .findFirst();
        } catch (PessimisticLockException | LockTimeoutException e) {
            throw new UserLockTimeoutException(e);
        }
    }

    private boolean isPostgres() {
        Boolean known = postgres;
        if (known == null) {
            known = entityManager.getEntityManagerFactory().unwrap(SessionFactoryImplementor.class)
                    .getJdbcServices().getDialect() instanceof PostgreSQLDialect;
            postgres = known;
        }
        return known;
    }
}
