package vn.thanhtuanle.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import vn.thanhtuanle.entity.User;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** {@code lockById}, the user's row lock, comes from the {@link UserRowLock} fragment. */
public interface UserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User>, UserRowLock {
    /**
     * The live account (status not 2, soft-deleted) with exactly this username: what a password login resolves. V6's
     * unique index {@code ux_users_username_lower} counts live rows only, so a soft-deleted account may keep the
     * username of a live one; among live rows there is at most one. A request's caller is resolved by id instead
     * ({@link #findLiveById}).
     */
    @Query("select u from User u where u.username = :username and u.status <> 2")
    Optional<User> findByUsername(@Param("username") String username);

    /**
     * The live account (status not 2, soft-deleted) with this id: whom a request's access token names by its
     * {@code uid} claim ({@code /auth/me}, logout, the current user). By id, not username: a deleted account's username
     * may belong to a live account now.
     */
    @Query("select u from User u where u.id = :id and u.status <> 2")
    Optional<User> findLiveById(@Param("id") UUID id);

    /**
     * Whether a live account (status not 2, soft-deleted) has this username in any case: the rows identity's V6 unique
     * index {@code ux_users_username_lower} covers, so the check refuses exactly what the index would.
     */
    @Query("select count(u) > 0 from User u where lower(u.username) = lower(:username) and u.status <> 2")
    boolean existsLiveByUsername(@Param("username") String username);

    /** Whether a live account has this email in any case (V6's {@code ux_users_email_lower}). */
    @Query("select count(u) > 0 from User u where lower(u.email) = lower(:email) and u.status <> 2")
    boolean existsLiveByEmail(@Param("email") String email);

    /** Whether a live account other than {@code id} has this email in any case (V6's {@code ux_users_email_lower}). */
    @Query("select count(u) > 0 from User u where lower(u.email) = lower(:email) and u.status <> 2 and u.id <> :id")
    boolean existsLiveByEmailAndIdNot(@Param("email") String email, @Param("id") UUID id);

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

    /**
     * Any account, live or not, with this Google id or with this email in any case. Case is folded with {@code lower()},
     * like the live lookup and V6's index (a derived {@code IgnoreCase} uses {@code upper()}, which differs for a few
     * letters such as ß/ẞ).
     */
    @Query("select count(u) > 0 from User u where u.googleId = :googleId or lower(u.email) = lower(:email)")
    boolean existsByGoogleIdOrEmailIgnoreCase(@Param("googleId") String googleId, @Param("email") String email);

    /**
     * The live account (status not 2) with this username in any case, for public profiles. V6's
     * {@code ux_users_username_lower} allows at most one such row, so a deleted account that kept the name never
     * shadows it. Case is folded with {@code lower()}, like the index.
     */
    @Query("select u from User u where lower(u.username) = lower(:username) and u.status <> 2")
    Optional<User> findLiveByUsernameIgnoreCase(@Param("username") String username);

    /** The live accounts (status not 2) among these ids, for public profiles. */
    @Query("select u from User u where u.id in :ids and u.status <> 2")
    List<User> findLiveByIdIn(@Param("ids") Collection<UUID> ids);

    long countByRoles_Id(UUID roleId);

    @Query("select u.id from User u join u.roles r where r.id = :roleId")
    List<UUID> findIdsByRoleId(@Param("roleId") UUID roleId);
}
