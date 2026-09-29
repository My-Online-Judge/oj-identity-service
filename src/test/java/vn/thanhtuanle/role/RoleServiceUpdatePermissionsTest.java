package vn.thanhtuanle.role;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.permission.PermissionRepository;
import vn.thanhtuanle.role.dto.RoleResponse;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceUpdatePermissionsTest {

    @Mock RoleRepository roleRepository;
    @Mock PermissionRepository permissionRepository;
    @Mock RoleMapper roleMapper;
    @Mock UserRepository userRepository;
    @Mock SessionRevoker sessionRevoker;

    @InjectMocks RoleService roleService;

    private Role role(String name) {
        Role r = Role.builder().name(name).build();
        r.setId(UUID.randomUUID());
        return r;
    }

    private Permission perm(String name) {
        Permission p = Permission.builder().name(name).build();
        p.setId(UUID.randomUUID());
        return p;
    }

    @Test
    void validReplace_persistsResolvedSet_andReturnsMappedResponse() {
        Role user = role("USER");
        when(roleRepository.findById(user.getId())).thenReturn(Optional.of(user));
        Permission pc = perm("problem:create");
        Permission pu = perm("problem:update");
        when(permissionRepository.findByNameIn(anyCollection())).thenReturn(List.of(pc, pu));
        when(roleMapper.toResponse(user)).thenReturn(RoleResponse.builder().name("USER").build());

        RoleResponse res = roleService.updatePermissions(user.getId(), Set.of("problem:create", "problem:update"));

        assertThat(res).isNotNull();
        assertThat(user.getPermissions()).containsExactlyInAnyOrder(pc, pu);
        verify(roleRepository).save(user);
    }

    @Test
    void unknownRole_throwsRoleNotExisted_neverSaves() {
        UUID id = UUID.randomUUID();
        when(roleRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.updatePermissions(id, Set.of("problem:create")))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_EXISTED));
        verify(roleRepository, never()).save(any());
    }

    @Test
    void adminRole_isImmutable_neverResolvesOrSaves() {
        Role admin = role("ADMIN");
        when(roleRepository.findById(admin.getId())).thenReturn(Optional.of(admin));

        assertThatThrownBy(() -> roleService.updatePermissions(admin.getId(), Set.of("problem:create")))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_IMMUTABLE));
        verify(permissionRepository, never()).findByNameIn(any());
        verify(roleRepository, never()).save(any());
    }

    @Test
    void unknownPermissionName_throwsPermissionNotExisted_neverSaves() {
        Role user = role("USER");
        when(roleRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(permissionRepository.findByNameIn(anyCollection())).thenReturn(List.of(perm("problem:create")));

        assertThatThrownBy(() -> roleService.updatePermissions(user.getId(),
                Set.of("problem:create", "does:not-exist")))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PERMISSION_NOT_EXISTED));
        verify(roleRepository, never()).save(any());
    }

    @Test
    void emptySet_clearsPermissions_withoutResolving() {
        Role user = role("USER");
        when(roleRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(roleMapper.toResponse(user)).thenReturn(RoleResponse.builder().name("USER").build());

        roleService.updatePermissions(user.getId(), Set.of());

        assertThat(user.getPermissions()).isEmpty();
        verify(permissionRepository, never()).findByNameIn(any());
        verify(roleRepository).save(user);
    }

    @Test
    void changingARolesPermissionsRevokesEveryHoldersAccessTokens() {
        Role moderator = role("MODERATOR");
        UUID holderA = UUID.randomUUID();
        UUID holderB = UUID.randomUUID();
        when(roleRepository.findById(moderator.getId())).thenReturn(Optional.of(moderator));
        when(permissionRepository.findByNameIn(anyCollection())).thenReturn(List.of(perm("problem:create")));
        when(userRepository.findIdsByRoleId(moderator.getId())).thenReturn(List.of(holderA, holderB));

        roleService.updatePermissions(moderator.getId(), Set.of("problem:create"));

        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(holderA, holderB));
    }
}
