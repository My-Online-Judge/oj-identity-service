package vn.thanhtuanle.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import vn.thanhtuanle.entity.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** {@code lockById}, the user's row lock, comes from the {@link UserRowLock} fragment. */
public interface UserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User>, UserRowLock {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    boolean existsByEmailAndIdNot(String email, UUID id);

    /**
     * The live account (status not 2, soft-deleted) with this email, whatever its case: the rows identity's V6 unique
     * index {@code ux_users_email_lower} covers, so there is at most one.
     */
    @Query("select u from User u where lower(u.email) = lower(:email) and u.status <> 2")
    Optional<User> findLiveByEmail(@Param("email") String email);

    /**
     * The live account (status not 2) linked to this Google id ({@code sub}): the rows V6's unique index
     * {@code ux_users_google_id} covers, so there is at most one.
     */
    @Query("select u from User u where u.googleId = :googleId and u.status <> 2")
    Optional<User> findLiveByGoogleId(@Param("googleId") String googleId);

    /** Any account, live or not, with this Google id or with this email in any case. */
    boolean existsByGoogleIdOrEmailIgnoreCase(String googleId, String email);

    long countByRoles_Id(UUID roleId);

    @Query("select u.id from User u join u.roles r where r.id = :roleId")
    List<UUID> findIdsByRoleId(@Param("roleId") UUID roleId);
}
