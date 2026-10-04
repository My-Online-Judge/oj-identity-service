package vn.thanhtuanle.role;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.permission.PermissionRepository;
import vn.thanhtuanle.role.dto.RoleResponse;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class RoleService {

    private static final String ADMIN_ROLE = "ADMIN";
    private static final String SYS_ROOT_ROLE = "SYS_ROOT";
    // Seeded roles referenced by code/seed data — they cannot be deleted.
    private static final Set<String> SYSTEM_ROLES = Set.of("ADMIN", "USER", "SYS_ROOT");
    private static final Pattern ROLE_NAME = Pattern.compile("^[A-Z][A-Z0-9_]*$");

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final RoleMapper roleMapper;
    private final SessionRevoker sessionRevoker;

    public List<RoleResponse> listRoles() {
        return roleMapper.toResponses(roleRepository.findAll(Sort.by("name")));
    }

    /**
     * Create a new role with no permissions. Name must be unique and match
     * {@code ^[A-Z][A-Z0-9_]*$}; permissions are granted afterwards via
     * {@link #updatePermissions(UUID, Set)}.
     */
    @Transactional
    public RoleResponse create(String name, String description) {
        String normalized = name == null ? "" : name.trim();
        if (!ROLE_NAME.matcher(normalized).matches()) {
            throw new AppException(ErrorCode.ROLE_NAME_INVALID);
        }
        if (roleRepository.findByName(normalized).isPresent()) {
            throw new AppException(ErrorCode.ROLE_EXISTED);
        }

        Role role = Role.builder()
                .name(normalized)
                .description(description == null ? null : description.trim())
                .permissions(new HashSet<>())
                .build();
        roleRepository.save(role);
        return roleMapper.toResponse(role);
    }

    /**
     * Delete a role. System roles ({@code ADMIN}/{@code USER}) are protected, and
     * a role still assigned to any user is refused (the admin must reassign first).
     * Deleting a role clears its {@code t_roles_permissions} rows (Role owns that join).
     */
    @Transactional
    public void delete(UUID roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_EXISTED));

        if (SYSTEM_ROLES.contains(role.getName())) {
            throw new AppException(ErrorCode.ROLE_PROTECTED);
        }
        if (userRepository.countByRoles_Id(roleId) > 0) {
            throw new AppException(ErrorCode.ROLE_IN_USE);
        }

        roleRepository.delete(role);
    }

    /**
     * Replace a role's permission set with the given permission names (replace-all, idempotent).
     * The ADMIN role is immutable — it always carries every permission (managed by migrations).
     */
    @Transactional
    public RoleResponse updatePermissions(UUID roleId, Set<String> permissionNames) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_EXISTED));

        if (ADMIN_ROLE.equals(role.getName()) || SYS_ROOT_ROLE.equals(role.getName())) {
            throw new AppException(ErrorCode.ROLE_IMMUTABLE);
        }

        Set<String> requested = permissionNames == null ? Set.of() : permissionNames;
        List<Permission> resolved = requested.isEmpty()
                ? List.of()
                : permissionRepository.findByNameIn(requested);
        if (resolved.size() != requested.size()) {
            throw new AppException(ErrorCode.PERMISSION_NOT_EXISTED);
        }

        role.setPermissions(new HashSet<>(resolved));
        roleRepository.save(role);
        // Every holder's token still lists the old permissions: revoke so they refresh into the new set.
        sessionRevoker.revokeAccessTokensAfterCommit(userRepository.findIdsByRoleId(roleId));
        return roleMapper.toResponse(role);
    }
}
