package vn.thanhtuanle.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceLogoutTest {

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

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String username, String token) {
        // What OjJwtAuthenticationFilter puts in the context for a verified access token.
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "RS256").subject(username).build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, Collections.emptyList(), username));
    }

    @Test
    void logout_blocklistsTheCurrentTokensJti_forItsRemainingLifetime() {
        String token = "current.access.token";
        authenticateAs("alice@example.com", token);
        User user = User.builder().username("alice@example.com").build();
        when(userRepository.findByUsername("alice@example.com")).thenReturn(Optional.of(user));
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);

        authService.logout();

        // The exact token the caller is holding is revoked until it would have expired.
        verify(tokenBlocklist).block("jti-current", 840_000L);
    }

    @Test
    void logout_stillRevokesStoredRefreshTokens() {
        String token = "current.access.token";
        authenticateAs("alice@example.com", token);
        UUID userId = UUID.randomUUID();
        User user = User.builder().username("alice@example.com").build();
        user.setId(userId);
        when(userRepository.findByUsername("alice@example.com")).thenReturn(Optional.of(user));
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);

        authService.logout();

        // Existing behaviour preserved: the DB-stored tokens (incl. refresh) are still cleared.
        verify(tokenRepository).deleteAllByUserId(userId);
    }
}
