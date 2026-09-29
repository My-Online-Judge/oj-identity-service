package vn.thanhtuanle.user;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceRolesTest {

    @Mock UserRepository userRepository;
    @Mock RoleRepository roleRepository;
    @Mock UserMapper userMapper;
    @Mock PasswordEncoder passwordEncoder;

    @Mock SessionRevoker sessionRevoker;

    @Spy @InjectMocks UserService userService;

    private final UUID currentUserId = UUID.randomUUID();

    @BeforeEach
    void stubCurrentUser() {
        User current = User.builder().username("admin").build();
        current.setId(currentUserId);
        lenient().doReturn(current).when(userService).getCurrentUser();
    }

    private User user(UUID id, String... roleNames) {
        User u = User.builder().username("target").build();
        u.setId(id);
        Set<Role> roles = new HashSet<>();
        for (String n : roleNames) {
            Role r = Role.builder().name(n).build();
            r.setId(UUID.randomUUID());
            roles.add(r);
        }
        u.setRoles(roles);
        return u;
    }

    @Test
    void updateRoles_replacesWholeSet() {
        UUID id = UUID.randomUUID();
        User u = user(id, "USER");
        UUID modId = UUID.randomUUID();
        Role moderator = Role.builder().name("MODERATOR").build();
        moderator.setId(modId);
        when(userRepository.findById(id)).thenReturn(Optional.of(u));
        when(roleRepository.findById(modId)).thenReturn(Optional.of(moderator));

        userService.updateRoles(id, Set.of(modId));

        assertThat(u.getRoles()).containsExactly(moderator);
        verify(userRepository).save(u);
    }

    @Test
    void updateRoles_self_throwsSelfModify() {
        when(userRepository.findById(currentUserId)).thenReturn(Optional.of(user(currentUserId)));

        assertThatThrownBy(() -> userService.updateRoles(currentUserId, Set.of(UUID.randomUUID())))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_SELF_MODIFY));
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateRoles_sysRootTarget_throwsProtected() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "SYS_ROOT")));

        assertThatThrownBy(() -> userService.updateRoles(id, Set.of(UUID.randomUUID())))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_PROTECTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateRoles_setContainsSysRoot_throwsNotAssignable() {
        UUID id = UUID.randomUUID();
        UUID sysRootId = UUID.randomUUID();
        Role sysRoot = Role.builder().name("SYS_ROOT").build();
        sysRoot.setId(sysRootId);
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));
        when(roleRepository.findById(sysRootId)).thenReturn(Optional.of(sysRoot));

        assertThatThrownBy(() -> userService.updateRoles(id, Set.of(sysRootId)))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_ASSIGNABLE));
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateRoles_unknownRole_throwsRoleNotExisted() {
        UUID id = UUID.randomUUID();
        UUID roleId = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));
        when(roleRepository.findById(roleId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.updateRoles(id, Set.of(roleId)))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_EXISTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void changingAUsersRolesRevokesTheirAccessTokens() {
        UUID id = UUID.randomUUID();
        UUID modId = UUID.randomUUID();
        Role moderator = Role.builder().name("MODERATOR").build();
        moderator.setId(modId);
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "USER")));
        when(roleRepository.findById(modId)).thenReturn(Optional.of(moderator));

        userService.updateRoles(id, Set.of(modId));

        verify(sessionRevoker).revokeAccessTokensAfterCommit(java.util.List.of(id));
    }
}
