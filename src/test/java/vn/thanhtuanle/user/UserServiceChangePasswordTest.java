package vn.thanhtuanle.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.util.HashSet;
import java.util.List;
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
class UserServiceChangePasswordTest {

    @Mock UserRepository userRepository;
    @Mock RoleRepository roleRepository;
    @Mock UserMapper userMapper;
    @Mock PasswordEncoder passwordEncoder;
    @Mock SessionRevoker sessionRevoker;
    @Mock TokenRepository tokenRepository;
    @Mock DefaultAdminPasswordGauge gauge;

    @InjectMocks UserService userService;

    private final UUID id = UUID.randomUUID();

    private User signedIn(String... roleNames) {
        User u = User.builder().username("me").password("HASH").build();
        u.setId(id);
        Set<Role> roles = new HashSet<>();
        for (String n : roleNames) {
            roles.add(Role.builder().name(n).build());
        }
        u.setRoles(roles);
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken("me", null, List.of()));
        when(userRepository.findByUsername("me")).thenReturn(Optional.of(u));
        return u;
    }

    @BeforeEach
    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private void assertCode(Runnable r, ErrorCode code) {
        assertThatThrownBy(r::run).isInstanceOfSatisfying(AppException.class,
                e -> assertThat(e.getErrorCode()).isEqualTo(code));
    }

    @Test
    void changesOwnPasswordAndRevokesEverySession() {
        User u = signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);
        when(passwordEncoder.encode("NewPass12")).thenReturn("NEW");

        userService.changeOwnPassword("OldPass12", "NewPass12");

        assertThat(u.getPassword()).isEqualTo("NEW");
        verify(userRepository).save(u);
        verify(tokenRepository).deleteAllByUserId(id);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(id));
        verify(gauge).refresh();
    }

    @Test
    void sysRootMayChangeOwnPassword() {
        signedIn("SYS_ROOT");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);
        when(passwordEncoder.encode("NewPass12")).thenReturn("NEW");

        userService.changeOwnPassword("OldPass12", "NewPass12");

        verify(tokenRepository).deleteAllByUserId(id);
    }

    @Test
    void wrongCurrentPassword401() {
        signedIn("USER");
        when(passwordEncoder.matches("Nope1234", "HASH")).thenReturn(false);

        assertCode(() -> userService.changeOwnPassword("Nope1234", "NewPass12"), ErrorCode.INVALID_CREDENTIALS);
        verify(userRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserId(any());
    }

    @Test
    void samePassword400() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);

        assertCode(() -> userService.changeOwnPassword("OldPass12", "OldPass12"), ErrorCode.PASSWORD_UNCHANGED);
        verify(userRepository, never()).save(any());
    }

    @Test
    void weakPassword400() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);

        assertCode(() -> userService.changeOwnPassword("OldPass12", "short"), ErrorCode.PASSWORD_INVALID);
        verify(userRepository, never()).save(any());
    }

    @Test
    void adminResetAlsoRevokes() {
        User target = User.builder().username("target").build();
        target.setId(id);
        target.setRoles(new HashSet<>());
        when(userRepository.findById(id)).thenReturn(Optional.of(target));
        when(passwordEncoder.encode("NewPass12")).thenReturn("NEW");

        userService.resetPassword(id, "NewPass12");

        verify(tokenRepository).deleteAllByUserId(id);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(id));
        verify(gauge).refresh();
    }
}
