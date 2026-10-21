package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.UserRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceRefreshTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "device-hash", "agent");
    private static final long REFRESH_TTL_MILLIS = 259_200_000L;

    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private TokenRepository tokenRepository;
    @Mock
    private TokenBlocklist tokenBlocklist;
    @Mock
    private SessionRevoker sessionRevoker;
    @Spy
    private Clock clock = Clock.fixed(Instant.parse("2026-10-20T05:00:00Z"), ZoneId.of("Asia/Ho_Chi_Minh"));
    @InjectMocks
    private AuthService authService;

    private final UUID storedId = UUID.randomUUID();
    /** When the presented refresh token expires: one refresh TTL after the login that started the session. */
    private static final Date SESSION_END = Date.from(Instant.parse("2026-10-22T09:00:00Z"));

    private User arrangeValidRefresh(String refreshToken, UUID userId) {
        User user = arrangeStoredRefresh(refreshToken, userId);
        when(tokenRepository.markRotated(storedId, now())).thenReturn(1);
        when(jwtUtil.generateToken(eq(user), anyLong())).thenReturn("new.access.token");
        when(jwtUtil.extractExpiration(refreshToken)).thenReturn(SESSION_END);
        when(jwtUtil.generateRefreshToken(user, SESSION_END)).thenReturn("new.refresh.token");
        return user;
    }

    private User arrangeStoredRefresh(String refreshToken, UUID userId) {
        User user = User.builder().username("alice@example.com").status(CommonStatus.ACTIVE.getValue()).build();
        user.setId(userId);
        Token stored = Token.builder().token(TokenHasher.sha256Hex(refreshToken)).tokenType(TokenType.REFRESH)
                .user(user).build();
        stored.setId(storedId);
        when(jwtUtil.isTokenExpired(refreshToken)).thenReturn(false);
        when(tokenRepository.findByToken(TokenHasher.sha256Hex(refreshToken))).thenReturn(Optional.of(stored));
        when(userRepository.lockById(userId)).thenReturn(Optional.of(user));
        return user;
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }

    @Test
    void refresh_deletesTheOldAccessRowBeforeSavingTheNewOnes() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // One live session must leave exactly one ACCESS row behind, not one per refresh.
        InOrder order = inOrder(tokenRepository);
        order.verify(tokenRepository).deleteAllByUserIdAndTokenType(userId, TokenType.ACCESS);
        order.verify(tokenRepository, times(2)).save(any(Token.class));
    }

    @Test
    void refresh_looksUpTheHashNotTheRawToken() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // Rows hold SHA-256 hex (V5), so a lookup by the raw token would never find a session.
        verify(tokenRepository).findByToken(TokenHasher.sha256Hex("valid.refresh.token"));
        verify(tokenRepository, never()).findByToken("valid.refresh.token");
    }

    @Test
    void refresh_rotatesTheRefreshToken() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);
        ReflectionTestUtils.setField(authService, "refreshTokenTtlMillis", REFRESH_TTL_MILLIS);

        AuthResponse response = authService.refreshAccessToken("valid.refresh.token", META);

        assertThat(response.getAccessToken()).isEqualTo("new.access.token");
        assertThat(response.getRefreshToken()).isEqualTo("new.refresh.token");
        verify(tokenRepository).markRotated(storedId, now());
        ArgumentCaptor<Token> saved = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository, times(2)).save(saved.capture());
        assertThat(saved.getAllValues())
                .extracting(Token::getTokenType, Token::getToken)
                .containsExactlyInAnyOrder(
                        tuple(TokenType.ACCESS, TokenHasher.sha256Hex("new.access.token")),
                        tuple(TokenType.REFRESH, TokenHasher.sha256Hex("new.refresh.token")));
        // Rotated rows are kept for reuse detection only while the token they held could still be presented.
        verify(tokenRepository).deleteRotatedBefore(userId, now().minus(Duration.ofMillis(REFRESH_TTL_MILLIS)));
        verify(tokenRepository, never()).deleteAllByUserId(any());
    }

    @Test
    void refresh_locksTheUserRowBeforeRotating() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // Serialises this rotation with any logout, login or reuse detection of the same user.
        InOrder order = inOrder(tokenRepository, userRepository);
        order.verify(tokenRepository).findByToken(TokenHasher.sha256Hex("valid.refresh.token"));
        order.verify(userRepository).lockById(userId);
        order.verify(tokenRepository).markRotated(storedId, now());
    }

    @Test
    void refresh_theSuccessorNeverOutlivesThePresentedToken() {
        UUID userId = UUID.randomUUID();
        User user = arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // The session ends one refresh TTL after login instead of sliding forever.
        verify(jwtUtil).generateRefreshToken(user, SESSION_END);
        verify(jwtUtil, never()).generateRefreshToken(any());
    }

    @Test
    void refresh_losingTheRotationRace_issuesNothing() {
        UUID userId = UUID.randomUUID();
        arrangeStoredRefresh("valid.refresh.token", userId);
        // A concurrent refresh rotated the row between our read and our update.
        when(tokenRepository.markRotated(storedId, now())).thenReturn(0);

        AuthResponse response = authService.refreshAccessToken("valid.refresh.token", META);

        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getRefreshToken()).isNull();
        verify(jwtUtil, never()).generateToken(any(), anyLong());
        verify(tokenRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserIdAndTokenType(any(), any());
    }

    @Test
    void refresh_gatesAndMintsWithTheRowItLocked() {
        UUID userId = UUID.randomUUID();
        User locked = arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // No second read by the token's subject: the status checked is the one read under the lock.
        verify(userRepository, never()).findByUsername(any());
        verify(jwtUtil).generateToken(eq(locked), anyLong());
    }

    @Test
    void refresh_blockedUser_isRejected_andMintsNoNewToken() {
        UUID userId = UUID.randomUUID();
        String refreshToken = "valid.refresh.token";
        // The token row's user was read before the lock; the account was disabled meanwhile.
        User before = User.builder().username("alice@example.com").status(CommonStatus.ACTIVE.getValue()).build();
        before.setId(userId);
        User user = User.builder().username("alice@example.com").status(CommonStatus.INACTIVE.getValue()).build();
        user.setId(userId);
        Token stored = Token.builder().token(TokenHasher.sha256Hex(refreshToken)).tokenType(TokenType.REFRESH)
                .user(before).build();
        when(jwtUtil.isTokenExpired(refreshToken)).thenReturn(false);
        when(tokenRepository.findByToken(TokenHasher.sha256Hex(refreshToken))).thenReturn(Optional.of(stored));
        when(userRepository.lockById(userId)).thenReturn(Optional.of(user));

        // A disabled/blocked account must be refused exactly like authenticateWithPassword
        // refuses it — the refresh path must not become a silent way to keep renewing a
        // blocked account's session.
        assertThatThrownBy(() -> authService.refreshAccessToken(refreshToken, META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_BLOCKED));

        verify(jwtUtil, never()).generateToken(any(), anyLong());
        verify(tokenRepository, never()).markRotated(any(), any());
        verify(tokenRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserIdAndTokenType(any(), any());
    }

    /** The successor access token's issue time is read before the lock that loads the user's roles (see I1). */
    @Test
    void refresh_issuesTheAccessTokenAtTheReadBeforeTheUsersStateIsLoaded() {
        UUID userId = UUID.randomUUID();
        User user = arrangeValidRefresh("valid.refresh.token", userId);
        long beforeTheLock = clock.millis();
        when(userRepository.lockById(userId)).thenAnswer(invocation -> {
            // Lenient: an implementation that reads the clock in the right place never asks again.
            lenient().doReturn(beforeTheLock + 5).when(clock).millis();
            return Optional.of(user);
        });

        authService.refreshAccessToken("valid.refresh.token", META);

        verify(jwtUtil).generateToken(user, beforeTheLock);
    }
}
