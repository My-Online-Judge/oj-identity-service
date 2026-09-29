package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceResetPasswordTest {

    @Mock UserRepository userRepository;
    @Mock RoleRepository roleRepository;
    @Mock UserMapper userMapper;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks UserService userService;

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
    void resetPassword_valid_encodesAndSaves() {
        UUID id = UUID.randomUUID();
        User u = user(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(u));
        when(passwordEncoder.encode("NewPass12")).thenReturn("ENC");

        userService.resetPassword(id, "NewPass12");

        assertThat(u.getPassword()).isEqualTo("ENC");
        verify(userRepository).save(u);
    }

    @Test
    void resetPassword_shortPassword_throwsPasswordInvalid() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id)));

        assertThatThrownBy(() -> userService.resetPassword(id, "short"))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PASSWORD_INVALID));
        verify(userRepository, never()).save(any());
    }

    @Test
    void resetPassword_sysRootTarget_throwsProtected() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.of(user(id, "SYS_ROOT")));

        assertThatThrownBy(() -> userService.resetPassword(id, "NewPass12"))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_PROTECTED));
        verify(userRepository, never()).save(any());
    }
}
