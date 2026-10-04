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
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.dto.UpdateUserRequest;
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
class UserServiceMutationTest {

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
        User u = User.builder().username("target").email("t@example.io").status(UserStatus.ACTIVE.getValue()).build();
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

    private UpdateUserRequest req(String name, String email, Integer status) {
        UpdateUserRequest r = new UpdateUserRequest();
        r.setName(name);
        r.setEmail(email);
        r.setStatus(status);
        return r;
    }

    @Test
    void update_changesNameAndEmail() {
        UUID id = UUID.randomUUID();
        User u = user(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(u));
        when(userRepository.existsByEmailAndIdNot("bob@example.io", id)).thenReturn(false);

        userService.update(id, req("Bob", "bob@example.io", null));

        assertThat(u.getName()).isEqualTo("Bob");
        assertThat(u.getEmail()).isEqualTo("bob@example.io");
        verify(userRepository).save(u);
    }

    @Test
    void update_duplicateEmail_throwsEmailExisted() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));
        when(userRepository.existsByEmailAndIdNot("dupe@example.io", id)).thenReturn(true);

        assertThatThrownBy(() -> userService.update(id, req(null, "dupe@example.io", null)))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.EMAIL_EXISTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void update_statusOnSelf_throwsSelfModify() {
        User self = user(currentUserId);
        when(userRepository.findById(currentUserId)).thenReturn(Optional.of(self));

        assertThatThrownBy(() -> userService.update(currentUserId, req(null, null, UserStatus.DISABLED.getValue())))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_SELF_MODIFY));
        verify(userRepository, never()).save(any());
    }

    @Test
    void update_sysRootTarget_throwsProtected() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "SYS_ROOT")));

        assertThatThrownBy(() -> userService.update(id, req("x", null, null)))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_PROTECTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateStatus_valid_setsStatus() {
        UUID id = UUID.randomUUID();
        User u = user(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(u));

        userService.updateStatus(id, UserStatus.DISABLED.getValue());

        assertThat(u.getStatus()).isEqualTo(UserStatus.DISABLED.getValue());
        verify(userRepository).save(u);
    }

    @Test
    void updateStatus_sysRootTarget_throwsProtected() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "SYS_ROOT")));

        assertThatThrownBy(() -> userService.updateStatus(id, UserStatus.DISABLED.getValue()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_PROTECTED));
    }

    @Test
    void updateStatus_deletedValue_throwsStatusInvalid() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        assertThatThrownBy(() -> userService.updateStatus(id, UserStatus.DELETED.getValue()))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_STATUS_INVALID));
        verify(userRepository, never()).save(any());
    }

    @Test
    void softDelete_valid_setsDeleted() {
        UUID id = UUID.randomUUID();
        User u = user(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(u));

        userService.softDelete(id);

        assertThat(u.getStatus()).isEqualTo(UserStatus.DELETED.getValue());
        verify(userRepository).save(u);
    }

    @Test
    void softDelete_self_throwsSelfModify() {
        when(userRepository.findById(currentUserId)).thenReturn(Optional.of(user(currentUserId)));

        assertThatThrownBy(() -> userService.softDelete(currentUserId))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_SELF_MODIFY));
        verify(userRepository, never()).save(any());
    }

    @Test
    void softDelete_sysRootTarget_throwsProtected() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "SYS_ROOT")));

        assertThatThrownBy(() -> userService.softDelete(id))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_PROTECTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void disablingAUserRevokesTheirAccessTokens() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        userService.updateStatus(id, UserStatus.DISABLED.getValue());

        verify(sessionRevoker).revokeAccessTokensAfterCommit(java.util.List.of(id));
    }

    @Test
    void reactivatingAUserRevokesNothing() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        userService.updateStatus(id, UserStatus.ACTIVE.getValue());

        verify(sessionRevoker, org.mockito.Mockito.never()).revokeAccessTokensAfterCommit(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void softDeletingAUserRevokesTheirAccessTokens() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        userService.softDelete(id);

        verify(sessionRevoker).revokeAccessTokensAfterCommit(java.util.List.of(id));
    }

    @Test
    void disablingAUserThroughTheEditFormRevokesTheirAccessTokens() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        userService.update(id, req(null, null, UserStatus.DISABLED.getValue()));

        verify(sessionRevoker).revokeAccessTokensAfterCommit(java.util.List.of(id));
    }

    @Test
    void editingOnlyTheProfileRevokesNothing() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        userService.update(id, req("Bob", null, null));

        verify(sessionRevoker, never()).revokeAccessTokensAfterCommit(any());
    }
}
