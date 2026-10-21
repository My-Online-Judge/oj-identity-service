package vn.thanhtuanle.auth;

import org.junit.jupiter.api.BeforeEach;
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
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.security.LoginRateLimiter.Attempt;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserLockTimeoutException;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
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

    private static final Instant NOW = Instant.parse("2026-10-21T01:02:03.500Z");
    @Spy Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @InjectMocks AuthService authService;

    private static final String HASH = "$2a$10$hash";
    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "probe/1.0");
    private static final Attempt ATTEMPT = new Attempt("admin", "1.2.3.4", 4, 4);

    @BeforeEach
    void reservesEveryAttempt() {
        lenient().when(loginRateLimiter.reserve("admin", META)).thenReturn(ATTEMPT);
    }

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
        when(jwtUtil.generateToken(eq(u), anyLong())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");
        when(userRepository.lockById(u.getId())).thenReturn(Optional.of(u));

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
        when(jwtUtil.generateToken(eq(u), anyLong())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");
        when(userRepository.lockById(u.getId())).thenReturn(Optional.of(u));

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
        verify(jwtUtil, never()).generateToken(any(), anyLong());
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
        verify(jwtUtil, never()).generateToken(any(), anyLong());
    }

    @Test
    void login_checksLimiter_recordsSuccess_andClearsCounter() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(eq(u), anyLong())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");
        when(userRepository.lockById(u.getId())).thenReturn(Optional.of(u));

        authService.authenticateWithPassword("admin", "secret", META);

        // The reservation taken before the password check is handed back: a success is not a failure.
        InOrder order = inOrder(loginRateLimiter, passwordEncoder);
        order.verify(loginRateLimiter).reserve("admin", META);
        order.verify(passwordEncoder).matches("secret", HASH);
        order.verify(loginRateLimiter).recordSuccess(ATTEMPT);
        verify(loginRateLimiter, never()).recordFailure(any());
        verify(loginAttemptService).record(eq("admin"), any(ClientMeta.class), eq(true), isNull());
        verify(sleeper, never()).sleep(any());
    }

    @Test
    void login_writesItsTokensInOneTransaction() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(jwtUtil.generateToken(eq(u), anyLong())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");
        when(userRepository.lockById(u.getId())).thenReturn(Optional.of(u));

        authService.authenticateWithPassword("admin", "secret", META);

        InOrder order = inOrder(userRepository, passwordEncoder, transactionManager, tokenRepository);
        order.verify(userRepository).findByUsername("admin");
        order.verify(passwordEncoder).matches("secret", HASH);
        order.verify(transactionManager).getTransaction(any());
        order.verify(userRepository).lockById(u.getId());
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
        when(loginRateLimiter.recordFailure(ATTEMPT)).thenReturn(Duration.ofSeconds(4));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));

        InOrder order = inOrder(loginRateLimiter, loginAttemptService, sleeper);
        order.verify(loginRateLimiter).recordFailure(ATTEMPT);
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

        verify(loginRateLimiter).recordFailure(ATTEMPT);
        verify(loginRateLimiter, never()).recordSuccess(any());
        verify(loginAttemptService).record(eq("admin"), any(ClientMeta.class), eq(false), eq("USER_NOT_EXISTED"));
    }

    @Test
    void aRefusedReservation_neverReachesTheDatabaseOrBCrypt() {
        // Locked, or five attempts of this pair already in flight.
        when(loginRateLimiter.reserve("admin", META)).thenThrow(new RateLimitedException(ErrorCode.RATE_LIMITED, 300));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.RATE_LIMITED));
        verifyNoInteractions(userRepository, passwordEncoder, sleeper);
        verify(loginRateLimiter, never()).recordFailure(any());
    }

    @Test
    void withEveryBackoffPermitTaken_aFailureIsAnsweredAtOnce() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);
        when(loginRateLimiter.recordFailure(ATTEMPT)).thenReturn(Duration.ofSeconds(4));
        Semaphore permits = (Semaphore) ReflectionTestUtils.getField(authService, "backoffPermits");
        assertThat(permits.availablePermits()).isEqualTo(AuthService.MAX_CONCURRENT_BACKOFFS);
        permits.drainPermits();

        // The counters and locks still apply; only the delay is skipped, so no burst can hold every worker thread.
        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));
        verify(loginRateLimiter).recordFailure(ATTEMPT);
        verifyNoInteractions(sleeper);
    }

    @Test
    void aLockTimeout_isNotAFailedAttempt_andHandsItsReservationBack() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(userRepository.lockById(u.getId())).thenThrow(new UserLockTimeoutException(new RuntimeException("55P03")));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_BUSY));

        verify(loginRateLimiter).release(ATTEMPT);
        verify(loginRateLimiter, never()).recordFailure(any());
        verify(loginRateLimiter, never()).recordSuccess(any());
        verifyNoInteractions(sleeper, loginAttemptService);
    }

    @Test
    void anUnexpectedError_handsTheReservationBack() {
        when(userRepository.findByUsername("admin"))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("database down"));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);

        verify(loginRateLimiter).release(ATTEMPT);
        verify(loginRateLimiter, never()).recordFailure(any());
        verifyNoInteractions(sleeper);
    }

    @Test
    void aFailingAudit_cannotSkipTheBackoff() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);
        when(loginRateLimiter.recordFailure(ATTEMPT)).thenReturn(Duration.ofSeconds(4));
        doThrow(new IllegalStateException("audit failed"))
                .when(loginAttemptService).record("admin", META, false, "USER_NOT_EXISTED");

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOf(RuntimeException.class);

        verify(sleeper).sleep(Duration.ofSeconds(4));
    }

    @Test
    void aBackoffHandsItsPermitBack() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);
        when(loginRateLimiter.recordFailure(ATTEMPT)).thenReturn(Duration.ofSeconds(4));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "wrong", META))
                .isInstanceOf(AppException.class);

        verify(sleeper).sleep(Duration.ofSeconds(4));
        Semaphore permits = (Semaphore) ReflectionTestUtils.getField(authService, "backoffPermits");
        assertThat(permits.availablePermits()).isEqualTo(AuthService.MAX_CONCURRENT_BACKOFFS);
    }

    @Test
    void aPasswordChangedSinceTheCheck_failsTheLogin_andWritesNothing() {
        User checked = admin(CommonStatus.ACTIVE.getValue(), HASH);
        User locked = admin(CommonStatus.ACTIVE.getValue(), "$2a$10$changed");
        locked.setId(checked.getId());
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(checked));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(userRepository.lockById(checked.getId())).thenReturn(Optional.of(locked));

        // The password BCrypt matched is no longer the account's: a change or reset committed in between.
        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));
        verify(tokenRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserId(any());
        verify(transactionManager).rollback(any());
        verify(loginRateLimiter).recordFailure(ATTEMPT);
        verify(loginRateLimiter, never()).recordSuccess(any());
    }

    @Test
    void anAccountDisabledSinceTheCheck_failsTheLogin_andWritesNothing() {
        User checked = admin(CommonStatus.ACTIVE.getValue(), HASH);
        User locked = admin(0, HASH);
        locked.setId(checked.getId());
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(checked));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(userRepository.lockById(checked.getId())).thenReturn(Optional.of(locked));

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_EXISTED));
        verify(tokenRepository, never()).save(any());
        verify(jwtUtil, never()).generateToken(any(), anyLong());
    }

    @Test
    void blockedUser_isRejected() {
        User u = admin(0, HASH); // not ACTIVE
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);

        assertThatThrownBy(() -> authService.authenticateWithPassword("admin", "secret", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_BLOCKED));
        verify(jwtUtil, never()).generateToken(any(), anyLong());
    }

    /**
     * The access token's issue time is read before the lock that loads the user's roles: a role change committed after
     * that read is revoked by the millisecond cutoff, even though the token is minted after the cutoff was written.
     */
    @Test
    void theAccessTokenIsIssuedAtTheReadBeforeTheUsersStateIsLoaded() {
        User u = admin(CommonStatus.ACTIVE.getValue(), HASH);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(u));
        when(passwordEncoder.matches("secret", HASH)).thenReturn(true);
        when(userRepository.lockById(u.getId())).thenAnswer(invocation -> {
            // Time passes between the state read and the mint.
            // Lenient: an implementation that reads the clock in the right place never asks again.
            lenient().doReturn(NOW.toEpochMilli() + 5).when(clock).millis();
            return Optional.of(u);
        });
        when(jwtUtil.generateToken(eq(u), anyLong())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");

        authService.authenticateWithPassword("admin", "secret", META);

        verify(jwtUtil).generateToken(u, NOW.toEpochMilli());
    }
}
