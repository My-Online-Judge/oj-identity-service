package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.dto.CreateUserRequest;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceCreateTest {

    @Mock UserRepository userRepository;
    @Mock RoleRepository roleRepository;
    @Mock UserMapper userMapper;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks UserService userService;

    private CreateUserRequest validReq() {
        CreateUserRequest req = new CreateUserRequest();
        req.setUsername("newuser");
        req.setName("New User");
        req.setEmail("new@example.io");
        req.setPassword("Passw0rd");
        return req;
    }

    @Test
    void validCreate_encodesPassword_defaultsActive_savesUser() {
        CreateUserRequest req = validReq();
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.io")).thenReturn(false);
        when(passwordEncoder.encode("Passw0rd")).thenReturn("ENC");

        userService.create(req);

        ArgumentCaptor<User> cap = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(cap.capture());
        User saved = cap.getValue();
        assertThat(saved.getUsername()).isEqualTo("newuser");
        assertThat(saved.getEmail()).isEqualTo("new@example.io");
        assertThat(saved.getPassword()).isEqualTo("ENC");
        assertThat(saved.getStatus()).isEqualTo(UserStatus.ACTIVE.getValue());
        assertThat(saved.getRoles()).isEmpty();
    }

    @Test
    void invalidUsername_throwsUsernameInvalid() {
        CreateUserRequest req = validReq();
        req.setUsername("ab");
        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USERNAME_INVALID));
        verify(userRepository, never()).save(any());
    }

    @Test
    void duplicateUsername_throwsUsernameExisted() {
        CreateUserRequest req = validReq();
        when(userRepository.existsByUsername("newuser")).thenReturn(true);
        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USERNAME_EXISTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void invalidEmail_throwsEmailInvalid() {
        CreateUserRequest req = validReq();
        req.setEmail("not-an-email");
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.EMAIL_INVALID));
        verify(userRepository, never()).save(any());
    }

    @Test
    void duplicateEmail_throwsEmailExisted() {
        CreateUserRequest req = validReq();
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.io")).thenReturn(true);
        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.EMAIL_EXISTED));
        verify(userRepository, never()).save(any());
    }

    @Test
    void shortPassword_throwsPasswordInvalid() {
        CreateUserRequest req = validReq();
        req.setPassword("short");
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.io")).thenReturn(false);
        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PASSWORD_INVALID));
        verify(userRepository, never()).save(any());
    }

    @Test
    void roleIdsContainingSysRoot_throwsRoleNotAssignable() {
        CreateUserRequest req = validReq();
        UUID sysRootId = UUID.randomUUID();
        req.setRoleIds(Set.of(sysRootId));
        Role sysRoot = Role.builder().name("SYS_ROOT").build();
        sysRoot.setId(sysRootId);
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.io")).thenReturn(false);
        when(roleRepository.findById(sysRootId)).thenReturn(Optional.of(sysRoot));

        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_ASSIGNABLE));
        verify(userRepository, never()).save(any());
    }

    @Test
    void unknownRoleId_throwsRoleNotExisted() {
        CreateUserRequest req = validReq();
        UUID roleId = UUID.randomUUID();
        req.setRoleIds(Set.of(roleId));
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("new@example.io")).thenReturn(false);
        when(roleRepository.findById(roleId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.create(req))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ROLE_NOT_EXISTED));
        verify(userRepository, never()).save(any());
    }
}
