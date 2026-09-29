package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceRefreshTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "device-hash", "agent");

    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private TokenRepository tokenRepository;
    @Mock
    private TokenBlocklist tokenBlocklist;
    @InjectMocks
    private AuthService authService;

    private User arrangeValidRefresh(String refreshToken, UUID userId) {
        User user = User.builder().username("alice@example.com").status(CommonStatus.ACTIVE.getValue()).build();
        user.setId(userId);
        Token stored = Token.builder().token(refreshToken).tokenType(TokenType.REFRESH).build();
        when(jwtUtil.isTokenExpired(refreshToken)).thenReturn(false);
        when(tokenRepository.findByToken(refreshToken)).thenReturn(Optional.of(stored));
        when(jwtUtil.extractUsername(refreshToken)).thenReturn("alice@example.com");
        when(userRepository.findByUsername("alice@example.com")).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken(user)).thenReturn("new.access.token");
        return user;
    }

    @Test
    void refresh_deletesTheOldAccessRowBeforeSavingTheNewOne() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);

        authService.refreshAccessToken("valid.refresh.token", META);

        // One live session must leave exactly one ACCESS row behind, not one per refresh.
        InOrder order = inOrder(tokenRepository);
        order.verify(tokenRepository).deleteAllByUserIdAndTokenType(userId, TokenType.ACCESS);
        order.verify(tokenRepository).save(any(Token.class));
    }

    @Test
    void refresh_leavesRefreshRowsAlone() {
        UUID userId = UUID.randomUUID();
        arrangeValidRefresh("valid.refresh.token", userId);

        AuthResponse response = authService.refreshAccessToken("valid.refresh.token", META);

        verify(tokenRepository, never()).deleteAllByUserIdAndTokenType(userId, TokenType.REFRESH);
        verify(tokenRepository, never()).deleteAllByUserId(any());
        // The refresh token is not rotated — the caller keeps using the one it sent.
        assertThat(response.getRefreshToken()).isEqualTo("valid.refresh.token");
        assertThat(response.getAccessToken()).isEqualTo("new.access.token");
    }

    @Test
    void refresh_blockedUser_isRejected_andMintsNoNewToken() {
        UUID userId = UUID.randomUUID();
        String refreshToken = "valid.refresh.token";
        User user = User.builder().username("alice@example.com").status(CommonStatus.INACTIVE.getValue()).build();
        user.setId(userId);
        Token stored = Token.builder().token(refreshToken).tokenType(TokenType.REFRESH).build();
        when(jwtUtil.isTokenExpired(refreshToken)).thenReturn(false);
        when(tokenRepository.findByToken(refreshToken)).thenReturn(Optional.of(stored));
        when(jwtUtil.extractUsername(refreshToken)).thenReturn("alice@example.com");
        when(userRepository.findByUsername("alice@example.com")).thenReturn(Optional.of(user));

        // A disabled/blocked account must be refused exactly like authenticateWithPassword
        // refuses it — the refresh path must not become a silent way to keep renewing a
        // blocked account's session.
        assertThatThrownBy(() -> authService.refreshAccessToken(refreshToken, META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_BLOCKED));

        verify(jwtUtil, never()).generateToken(any());
        verify(tokenRepository, never()).save(any());
        verify(tokenRepository, never()).deleteAllByUserIdAndTokenType(any(), any());
    }
}
