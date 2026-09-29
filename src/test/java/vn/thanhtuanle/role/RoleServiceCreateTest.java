package vn.thanhtuanle.role;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.permission.PermissionRepository;
import vn.thanhtuanle.role.dto.RoleResponse;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceCreateTest {

    @Mock RoleRepository roleRepository;
    @Mock PermissionRepository permissionRepository;
    @Mock UserRepository userRepository;
    @Mock RoleMapper roleMapper;

    @InjectMocks RoleService roleService;

    @Test
    void validName_persistsEmptyRole_andReturnsMappedResponse() {
        when(roleRepository.findByName("MODERATOR")).thenReturn(Optional.empty());
        when(roleMapper.toResponse(any(Role.class)))
                .thenReturn(RoleResponse.builder().name("MODERATOR").build());

        RoleResponse res = roleService.create("MODERATOR", "Content moderator");

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        Role saved = captor.getValue();
        assertThat(saved.getName()).isEqualTo("MODERATOR");
        assertThat(saved.getDescription()).isEqualTo("Content moderator");
        assertThat(saved.getPermissions()).isEmpty();
        assertThat(res.getName()).isEqualTo("MODERATOR");
    }

    @Test
    void nameAndDescription_trimmed_beforeUniquenessCheckAndPersist() {
        when(roleRepository.findByName("MODERATOR")).thenReturn(Optional.empty());
        when(roleMapper.toResponse(any(Role.class)))
                .thenReturn(RoleResponse.builder().name("MODERATOR").build());

        roleService.create("  MODERATOR  ", "  trimmed desc  ");

        verify(roleRepository).findByName("MODERATOR");
        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        assertThat(captor.getValue().getName()).isEqualTo("MODERATOR");
        assertThat(captor.getValue().getDescription()).isEqualTo("trimmed desc");
    }

    @Test
    void invalidName_throwsRoleNameInvalid_neverTouchesRepo() {
        for (String bad : new String[] {"", "   ", "moderator", "1ROLE", "TWO WORDS", "kebab-case"}) {
            assertThatThrownBy(() -> roleService.create(bad, null))
                    .isInstanceOfSatisfying(AppException.class,
                            e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NAME_INVALID));
        }
        verify(roleRepository, never()).findByName(anyString());
        verify(roleRepository, never()).save(any());
    }

    @Test
    void duplicateName_throwsRoleExisted_neverSaves() {
        when(roleRepository.findByName("ADMIN"))
                .thenReturn(Optional.of(Role.builder().name("ADMIN").build()));

        assertThatThrownBy(() -> roleService.create("ADMIN", null))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_EXISTED));
        verify(roleRepository, never()).save(any());
    }
}
