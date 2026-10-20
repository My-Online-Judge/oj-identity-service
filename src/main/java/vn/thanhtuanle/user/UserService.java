package vn.thanhtuanle.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.thanhtuanle.auth.Caller;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.payload.PageResponse;
import vn.thanhtuanle.oj.common.web.payload.PageSizes;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.oj.common.web.error.ResourceNotFoundException;
import vn.thanhtuanle.user.dto.CreateUserRequest;
import vn.thanhtuanle.user.dto.PublicProfileResponse;
import vn.thanhtuanle.user.dto.UpdateUserRequest;
import vn.thanhtuanle.user.dto.UserResponse;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private static final String SYS_ROOT = "SYS_ROOT";
    private static final Pattern USERNAME = Pattern.compile("^[a-zA-Z0-9_]{3,32}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final SessionRevoker sessionRevoker;
    private final TokenRepository tokenRepository;
    private final DefaultAdminPasswordGauge defaultAdminPasswordGauge;
    private final LoginRateLimiter loginRateLimiter;

    /** A lazy reference by id — no query — for linking an entity to the user behind the request. */
    public User getReference(UUID id) {
        return userRepository.getReferenceById(id);
    }

    /** The signed-in user: the live account the access token names by id ({@link Caller}), never by username. */
    public User getCurrentUser() {
        return Caller.id().flatMap(userRepository::findLiveById)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
    }

    // ----- read -----

    public PageResponse<UserResponse> list(int page, int size, String search, Integer status, UUID roleId,
            LocalDate createdFrom, LocalDate createdTo) {
        Pageable pageable = PageRequest.of(page, PageSizes.cap(size), Sort.by("createdAt").descending());
        Page<UserResponse> dtoPage = userRepository
                .findAll(UserSpecifications.filter(search, status, roleId, createdFrom, createdTo), pageable)
                .map(userMapper::toResponse);
        return PageResponse.of(dtoPage);
    }

    public UserResponse getById(UUID id) {
        return userRepository.findById(id)
                .map(userMapper::toResponse)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    /** Anyone's view of a live account (disabled included) by username in any case; deleted or unknown is 404. */
    @Transactional(readOnly = true)
    public PublicProfileResponse publicProfile(String username) {
        return userRepository.findLiveByUsernameIgnoreCase(username)
                .map(UserService::toPublicProfile)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    /** Public views of the live accounts among these ids; unknown and deleted ones are left out. */
    @Transactional(readOnly = true)
    public List<PublicProfileResponse> publicProfiles(List<UUID> ids) {
        return userRepository.findLiveByIdIn(ids).stream().map(UserService::toPublicProfile).toList();
    }

    private static PublicProfileResponse toPublicProfile(User u) {
        return new PublicProfileResponse(u.getId(), u.getUsername(), u.getName(), u.getAvatar(), u.getCreatedAt());
    }

    // ----- create -----

    @Transactional
    public UserResponse create(CreateUserRequest req) {
        String username = req.getUsername() == null ? "" : req.getUsername().trim();
        if (!USERNAME.matcher(username).matches()) {
            throw new AppException(ErrorCode.USERNAME_INVALID);
        }
        // Live accounts only and in any case, like V6's unique indexes: a deleted account's name may be taken again.
        if (userRepository.existsLiveByUsername(username)) {
            throw new AppException(ErrorCode.USERNAME_EXISTED);
        }
        String email = req.getEmail() == null ? "" : req.getEmail().trim();
        if (!EMAIL.matcher(email).matches()) {
            throw new AppException(ErrorCode.EMAIL_INVALID);
        }
        if (userRepository.existsLiveByEmail(email)) {
            throw new AppException(ErrorCode.EMAIL_EXISTED);
        }
        validatePassword(req.getPassword());

        Set<Role> roles = resolveRoles(req.getRoleIds());
        int status = req.getStatus() == null ? UserStatus.ACTIVE.getValue() : activeOrDisabled(req.getStatus());

        User user = User.builder()
                .username(username)
                .name(req.getName() == null ? null : req.getName().trim())
                .email(email)
                .password(passwordEncoder.encode(req.getPassword()))
                .status(status)
                .enabledMfa(false)
                .roles(roles)
                .build();
        // Flushed now: V6's unique indexes (usernames and emails in any case) refuse a taken one here, as a 409.
        userRepository.saveAndFlush(user);
        log.info("Created user {}", username);
        return userMapper.toResponse(user);
    }

    // ----- update -----

    @Transactional
    public UserResponse update(UUID id, UpdateUserRequest req) {
        User user = loadModifiable(id);
        if (req.getName() != null) {
            user.setName(req.getName().trim());
        }
        if (req.getEmail() != null) {
            String email = req.getEmail().trim();
            if (!EMAIL.matcher(email).matches()) {
                throw new AppException(ErrorCode.EMAIL_INVALID);
            }
            if (userRepository.existsLiveByEmailAndIdNot(email, id)) {
                throw new AppException(ErrorCode.EMAIL_EXISTED);
            }
            user.setEmail(email);
        }
        if (req.getStatus() != null) {
            assertNotSelf(id);
            user.setStatus(activeOrDisabled(req.getStatus()));
        }
        // Flushed now: V6's unique index refuses an email another account has in any case, as a 409.
        userRepository.saveAndFlush(user);
        // The edit form can disable too; like updateStatus, that must end the user's sessions now.
        if (req.getStatus() != null && user.getStatus() != UserStatus.ACTIVE.getValue()) {
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(id));
        }
        return userMapper.toResponse(user);
    }

    @Transactional
    public UserResponse updateStatus(UUID id, Integer status) {
        User user = loadModifiable(id);
        assertNotSelf(id);
        user.setStatus(activeOrDisabled(status));
        userRepository.save(user);
        if (user.getStatus() != UserStatus.ACTIVE.getValue()) {
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(id));
        }
        return userMapper.toResponse(user);
    }

    @Transactional
    public UserResponse updateRoles(UUID id, Set<UUID> roleIds) {
        User user = loadModifiable(id);
        assertNotSelf(id);
        user.setRoles(resolveRoles(roleIds));
        userRepository.save(user);
        sessionRevoker.revokeAccessTokensAfterCommit(List.of(id));
        return userMapper.toResponse(user);
    }

    @Transactional
    public void resetPassword(UUID id, String newPassword) {
        User user = loadModifiable(id);
        validatePassword(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        endSessions(user.getId());
        log.info("Reset password for user {}", user.getUsername());
    }

    /**
     * Change the signed-in user's own password (SYS_ROOT included); every session of theirs ends. Wrong current
     * passwords are throttled like logins (5 per 5 minutes, then 429 for 15), so a stolen session cannot guess it.
     */
    @Transactional
    public void changeOwnPassword(String current, String next) {
        User user = getCurrentUser();
        loginRateLimiter.assertPasswordChangeAllowed(user.getId());
        if (!passwordEncoder.matches(current, user.getPassword())) {
            loginRateLimiter.recordPasswordChangeFailure(user.getId());
            throw new AppException(ErrorCode.CURRENT_PASSWORD_INCORRECT);
        }
        if (next != null && next.equals(current)) {
            throw new AppException(ErrorCode.PASSWORD_UNCHANGED);
        }
        validatePassword(next);
        user.setPassword(passwordEncoder.encode(next));
        userRepository.save(user);
        endSessions(user.getId());
        log.info("User {} changed their password", user.getUsername());
    }

    /** A new credential invalidates refresh tokens now and live access tokens once the transaction commits. */
    private void endSessions(UUID userId) {
        userRepository.lockById(userId);
        tokenRepository.deleteAllByUserId(userId);
        sessionRevoker.revokeAccessTokensAfterCommit(List.of(userId));
        // A BCrypt check (~100 ms): after the commit, not while the user's row is locked.
        afterCommit(defaultAdminPasswordGauge::refresh);
    }

    private static void afterCommit(Runnable action) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    action.run();
                }
            });
        } else {
            action.run();
        }
    }

    @Transactional
    public void softDelete(UUID id) {
        User user = loadModifiable(id);
        assertNotSelf(id);
        user.setStatus(UserStatus.DELETED.getValue());
        userRepository.save(user);
        sessionRevoker.revokeAccessTokensAfterCommit(List.of(id));
        log.info("Soft-deleted user {}", user.getUsername());
    }

    // ----- helpers -----

    /** Load a user for modification, refusing missing users (404) and protected SYS_ROOT accounts (409). */
    private User loadModifiable(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
        if (hasSysRoot(user)) {
            throw new AppException(ErrorCode.USER_PROTECTED);
        }
        return user;
    }

    private void assertNotSelf(UUID id) {
        if (id.equals(getCurrentUser().getId())) {
            throw new AppException(ErrorCode.USER_SELF_MODIFY);
        }
    }

    private static boolean hasSysRoot(User user) {
        return user.getRoles() != null
                && user.getRoles().stream().anyMatch(r -> SYS_ROOT.equals(r.getName()));
    }

    /** Resolve role ids to entities; every id must exist and none may be SYS_ROOT (seed-only). */
    private Set<Role> resolveRoles(Set<UUID> roleIds) {
        Set<Role> roles = new HashSet<>();
        if (roleIds == null || roleIds.isEmpty()) {
            return roles;
        }
        for (UUID roleId : roleIds) {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_EXISTED));
            if (SYS_ROOT.equals(role.getName())) {
                throw new AppException(ErrorCode.ROLE_NOT_ASSIGNABLE);
            }
            roles.add(role);
        }
        return roles;
    }

    private static void validatePassword(String password) {
        String pwd = password == null ? "" : password;
        if (pwd.length() < 8 || !pwd.matches(".*[a-zA-Z].*") || !pwd.matches(".*\\d.*")) {
            throw new AppException(ErrorCode.PASSWORD_INVALID);
        }
    }

    /** Accept only ACTIVE/DISABLED for status writes; DELETED is reachable only via soft-delete. */
    private static int activeOrDisabled(Integer status) {
        if (status == null
                || (status != UserStatus.ACTIVE.getValue() && status != UserStatus.DISABLED.getValue())) {
            throw new AppException(ErrorCode.USER_STATUS_INVALID);
        }
        return status;
    }
}
