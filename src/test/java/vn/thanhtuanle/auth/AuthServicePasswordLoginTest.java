package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestTemplate;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServicePasswordLoginTest {

    @Mock UserRepository userRepository;
    @Mock JwtUtil jwtUtil;
    @Mock TokenRepository tokenRepository;
    @Mock RoleRepository roleRepository;
    @Mock UserMapper userMapper;
    @Mock RestTemplate restTemplate;
    @Mock TokenBlocklist tokenBlocklist;
    @Mock PasswordEncoder passwordEncoder;
    @Mock LoginRateLimiter loginRateLimiter;
    @Mock LoginAttemptService loginAttemptService;
    @Mock Sleeper sleeper;

    private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
    @Spy TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);

    @InjectMocks AuthService authService;

    private static final String HASH = "$2a$10$hash";
    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "probe/1.0");

    private User admin(Integer status, String password) {
        User u = User.builder().username("admin").password(password).status(status).build();
        u.setId(UUID.randomUUID());
        return u;
    }

    @Test
    void validCredentials_mintTokens_andRecordThem() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(u)).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");

        AuthResponse res = authService.authenticateWithPassword("admin", "secret", META);

        assertThat(res.getAccessToken()).isEqualTo("AT");
        assertThat(res.getRefreshToken()).isEqualTo("RT");
        verify(tokenRepository).deleteAllByUserId(u.getId());   // old tokens revoked
        verify(tokenRepository, times(2)).save(any());          // access + refresh recorded
    }

    @Test
    void login_storesHashesNotTokens() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(u)).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");

        authService.authenticateWithPassword("admin", "secret", META);

        // A database leak must not hand out live sessions: rows keep SHA-256 hex, the client keeps the token.
        ArgumentCaptor<Token> saved = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository, times(2)).save(saved.capture());
        assertThat(saved.getAllValues()).extracting(Token::getToken)
                .containsExactly(TokenHasher.sha256Hex("AT"), TokenHasher.sha256Hex("RT"));
    }

    @Test
    void wrongPassword_isRejected_withGenericError_andMintsNoToken() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));
        verify(jwtUtil, never()).generateToken(any());
    }

    @Test
    void unknownUser_sameGenericError_neverChecksPassword() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.authenticateWithPassword("ghost", "x", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void googleOnlyUser_hasNoPassword_cannotPasswordLogin() {
        User u = admin(CommonStatus.ACTIVE.getValue(), null);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "x", META))
                .isInstanceOf(AppException.class);
        verify(jwtUtil, never()).generateToken(any());
    }

    @Test
    void login_checksLimiter_recordsSuccess_andClearsCounter() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(u)).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");

        authService.authenticateWithPassword("admin", "secret", META);

        verify(loginRateLimiter).assertAllowed(eq("admin"), any(ClientMeta.class));
        verify(loginRateLimiter).clear("admin", META);
        verify(loginAttemptService).record(eq("admin"), any(ClientMeta.class), eq(true), isNull());
        verify(sleeper, never()).sleep(any());
    }

    @Test
    void login_writesItsTokensInOneTransaction() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(u)).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");

        authService.authenticateWithPassword("admin", "secret", META);

        InOrder order = inOrder(userRepository, passwordEncoder, transactionManager, tokenRepository);
        order.verify(userRepository).findByUsername("admin");
        order.verify(passwordEncoder).matches("secret", HASH);
        order.verify(transactionManager).getTransaction(any());
        order.verify(tokenRepository).deleteAllByUserId(u.getId());
        order.verify(tokenRepository, times(2)).save(any());
        order.verify(userRepository).save(u);
        order.verify(transactionManager).commit(any());
    }

    @Test
    void badPassword_sleepsTheBackoffAfterRecordingIt_thenRejects() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);
        when(loginRateLimiter.recordFailure("admin", META)).thenReturn(Duration.ofSeconds(4));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));

        InOrder order = inOrder(loginRateLimiter, loginAttemptService, sleeper);
        order.verify(loginRateLimiter).recordFailure("admin", META);
        order.verify(loginAttemptService).record("admin", META, false, "USER_NOT_EXISTED");
        order.verify(sleeper).sleep(Duration.ofSeconds(4));
        verifyNoInteractions(transactionManager);
    }

    @Test
    void badPassword_recordsFailure_andAuditsIt() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOf(AppException.class);

        verify(loginRateLimiter).recordFailure(eq("admin"), any(ClientMeta.class));
        verify(loginAttemptService).record(eq("admin"), any(ClientMeta.class), eq(false), eq("USER_NOT_EXISTED"));
    }

    @Test
    void lockedKey_rejectsBeforeTouchingTheRepository() {
        doThrow(new AppException(ErrorCode.RATE_LIMITED))
                .when(loginRateLimiter).assertAllowed(eq("admin"), any(ClientMeta.class));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED));
        verifyNoInteractions(userRepository);
    }

    @Test
    void blockedUser_isRejected() {
        User u = admin(0, HASH); // not ACTIVE
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_BLOCKED));
        verify(jwtUtil, never()).generateToken(any());
    }
}
