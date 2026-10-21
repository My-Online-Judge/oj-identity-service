package vn.thanhtuanle.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.security.LoginRateLimiter.PasswordChangeAttempt;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
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
    @Mock LoginRateLimiter loginRateLimiter;

    @InjectMocks UserService userService;

    private final UUID id = UUID.randomUUID();
    /** The place every change takes in the limiter before BCrypt runs. */
    private final PasswordChangeAttempt attempt = new PasswordChangeAttempt(id, 1, false, null);

    private User signedIn(String... roleNames) {
        User u = User.builder().username("me").password("HASH").build();
        u.setId(id);
        Set<Role> roles = new HashSet<>();
        for (String n : roleNames) {
            roles.add(Role.builder().name(n).build());
        }
        u.setRoles(roles);
        // What OjJwtAuthenticationFilter puts in the context for the user's access token: the caller is its uid.
        Jwt jwt = Jwt.withTokenValue("access.token").header("alg", "RS256").subject("me")
                .claim("uid", id.toString()).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of(), "me"));
        when(userRepository.findLiveById(id)).thenReturn(Optional.of(u));
        lenient().when(loginRateLimiter.reservePasswordChange(id)).thenReturn(attempt);
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
        // Under the user's row lock, so a concurrent refresh cannot leave a successor behind.
        var order = inOrder(userRepository, tokenRepository);
        order.verify(userRepository).lockById(id);
        order.verify(tokenRepository).deleteAllByUserId(id);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(id));
        verify(gauge).refresh();
    }

    @Test
    void theDefaultAdminGaugeRefreshesOnlyAfterCommit() {
        // Its BCrypt check (~100 ms) must not run while the user's row is locked.
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);
        when(passwordEncoder.encode("NewPass12")).thenReturn("NEW");
        TransactionSynchronizationManager.initSynchronization();
        try {
            userService.changeOwnPassword("OldPass12", "NewPass12");

            verify(gauge, never()).refresh();
            TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);
            verify(gauge).refresh();
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }
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
    void wrongCurrentPassword400() {
        signedIn("USER");
        when(passwordEncoder.matches("Nope1234", "HASH")).thenReturn(false);

        assertCode(() -> userService.changeOwnPassword("Nope1234", "NewPass12"), ErrorCode.CURRENT_PASSWORD_INCORRECT);
        verify(userRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserId(any());
    }

    @Test
    void aWrongCurrentPasswordRecordsAFailure() {
        signedIn("USER");
        when(passwordEncoder.matches("Nope1234", "HASH")).thenReturn(false);

        assertCode(() -> userService.changeOwnPassword("Nope1234", "NewPass12"), ErrorCode.CURRENT_PASSWORD_INCORRECT);

        // The place is taken before BCrypt runs, and a failure keeps it.
        var order = inOrder(loginRateLimiter, passwordEncoder);
        order.verify(loginRateLimiter).reservePasswordChange(id);
        order.verify(passwordEncoder).matches("Nope1234", "HASH");
        order.verify(loginRateLimiter).recordPasswordChangeFailure(attempt);
        verify(loginRateLimiter, never()).releasePasswordChange(any());
    }

    @Test
    void aRefusedReserveRunsNoBcrypt() {
        signedIn("USER");
        doThrow(new RateLimitedException(ErrorCode.PASSWORD_CHANGE_RATE_LIMITED, 600))
                .when(loginRateLimiter).reservePasswordChange(id);

        assertThatThrownBy(() -> userService.changeOwnPassword("OldPass12", "NewPass12"))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.PASSWORD_CHANGE_RATE_LIMITED);
                    assertThat(e.getErrorCode().getStatusCode().value()).isEqualTo(429);
                });
        verify(passwordEncoder, never()).matches(any(), any());
        verify(loginRateLimiter, never()).recordPasswordChangeFailure(any());
        verify(loginRateLimiter, never()).releasePasswordChange(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void aSuccessHandsThePlaceBack() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);
        when(passwordEncoder.encode("NewPass12")).thenReturn("NEW");

        userService.changeOwnPassword("OldPass12", "NewPass12");

        verify(loginRateLimiter, never()).recordPasswordChangeFailure(any());
        verify(loginRateLimiter).releasePasswordChange(attempt);
    }

    @Test
    void anUnchangedPasswordHandsThePlaceBack() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);

        assertCode(() -> userService.changeOwnPassword("OldPass12", "OldPass12"), ErrorCode.PASSWORD_UNCHANGED);
        verify(userRepository, never()).save(any());
        verify(loginRateLimiter, never()).recordPasswordChangeFailure(any());
        verify(loginRateLimiter).releasePasswordChange(attempt);
    }

    @Test
    void weakPassword400_handsThePlaceBack() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);

        assertCode(() -> userService.changeOwnPassword("OldPass12", "short"), ErrorCode.PASSWORD_INVALID);
        verify(userRepository, never()).save(any());
        verify(loginRateLimiter).releasePasswordChange(attempt);
    }

    @Test
    void anExceptionAfterTheCheckHandsThePlaceBack() {
        signedIn("USER");
        when(passwordEncoder.matches("OldPass12", "HASH")).thenReturn(true);
        when(passwordEncoder.encode("NewPass12")).thenThrow(new IllegalStateException("boom"));

        assertThatThrownBy(() -> userService.changeOwnPassword("OldPass12", "NewPass12"))
                .isInstanceOf(IllegalStateException.class);
        verify(loginRateLimiter).releasePasswordChange(attempt);
        verify(loginRateLimiter, never()).recordPasswordChangeFailure(any());
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
