package vn.thanhtuanle.role;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.permission.PermissionRepository;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceDeleteTest {

    @Mock RoleRepository roleRepository;
    @Mock PermissionRepository permissionRepository;
    @Mock UserRepository userRepository;
    @Mock RoleMapper roleMapper;

    @InjectMocks RoleService roleService;

    private Role role(String name) {
        Role r = Role.builder().name(name).build();
        r.setId(UUID.randomUUID());
        return r;
    }

    @Test
    void systemRole_admin_isProtected_neverCountsOrDeletes() {
        Role admin = role("ADMIN");
        when(roleRepository.findById(admin.getId())).thenReturn(Optional.of(admin));

        assertThatThrownBy(() -> roleService.delete(admin.getId()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_PROTECTED));
        verify(userRepository, never()).countByRoles_Id(any());
        verify(roleRepository, never()).delete(any());
    }

    @Test
    void systemRole_user_isProtected_neverDeletes() {
        Role user = role("USER");
        when(roleRepository.findById(user.getId())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> roleService.delete(user.getId()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_PROTECTED));
        verify(roleRepository, never()).delete(any());
    }

    @Test
    void systemRole_sysRoot_isProtected_neverDeletes() {
        Role sysRoot = role("SYS_ROOT");
        when(roleRepository.findById(sysRoot.getId())).thenReturn(Optional.of(sysRoot));

        assertThatThrownBy(() -> roleService.delete(sysRoot.getId()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_PROTECTED));
        verify(roleRepository, never()).delete(any());
    }

    @Test
    void unknownRole_throwsRoleNotExisted() {
        UUID id = UUID.randomUUID();
        when(roleRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> roleService.delete(id))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_EXISTED));
        verify(roleRepository, never()).delete(any());
    }

    @Test
    void roleStillHeldByUsers_throwsRoleInUse_neverDeletes() {
        Role custom = role("MODERATOR");
        when(roleRepository.findById(custom.getId())).thenReturn(Optional.of(custom));
        when(userRepository.countByRoles_Id(custom.getId())).thenReturn(3L);

        assertThatThrownBy(() -> roleService.delete(custom.getId()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_IN_USE));
        verify(roleRepository, never()).delete(any());
    }

    @Test
    void unusedCustomRole_isDeleted() {
        Role custom = role("MODERATOR");
        when(roleRepository.findById(custom.getId())).thenReturn(Optional.of(custom));
        when(userRepository.countByRoles_Id(custom.getId())).thenReturn(0L);

        roleService.delete(custom.getId());

        verify(roleRepository).delete(custom);
    }
}
