package vn.thanhtuanle.auth;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.UserRepository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
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
    @Mock
    private SessionRevoker sessionRevoker;
    /** The sessions end in a transaction of their own (a mocked manager: no database here). */
    @Spy
    private TransactionTemplate transactionTemplate = new TransactionTemplate(mock(PlatformTransactionManager.class));
    @InjectMocks
    private AuthService authService;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /** alice, signed in with this access token: what OjJwtAuthenticationFilter puts in the context for it. */
    private User signedIn(String token) {
        User user = User.builder().username("alice@example.com").build();
        user.setId(UUID.randomUUID());
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "RS256").subject(user.getUsername())
                .claim("uid", user.getId().toString()).build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, Collections.emptyList(), user.getUsername()));
        when(userRepository.findLiveById(user.getId())).thenReturn(Optional.of(user));
        return user;
    }

    @Test
    void logout_blocklistsTheCurrentTokensJti_forItsRemainingLifetime() {
        String token = "current.access.token";
        signedIn(token);
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);

        authService.logout(null);

        // The exact token the caller is holding is revoked until it would have expired.
        verify(tokenBlocklist).block("jti-current", 840_000L);
    }

    @Test
    void logout_stillRevokesStoredRefreshTokens() {
        String token = "current.access.token";
        UUID userId = signedIn(token).getId();
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);

        authService.logout(null);

        // Existing behaviour preserved: the DB-stored tokens (incl. refresh) are still cleared.
        verify(tokenRepository).deleteAllByUserId(userId);
    }

    @Test
    void logout_writesTheRevocationCutoff() {
        String token = "current.access.token";
        UUID userId = signedIn(token).getId();
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);

        authService.logout(null);

        // Logout ends every device's session, not only this one: access tokens the user holds elsewhere
        // (minted before now) are stripped by the gateway once the transaction commits.
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(userId));
    }

    @Test
    void logout_locksTheUserRowBeforeDeletingItsTokens() {
        String token = "current.access.token";
        UUID userId = signedIn(token).getId();

        authService.logout(null);

        // A rotation running at the same time must not slip a successor past the delete.
        InOrder order = inOrder(userRepository, tokenRepository);
        order.verify(userRepository).lockById(userId);
        order.verify(tokenRepository).deleteAllByUserId(userId);
    }

    @Test
    void logout_withAnExpiredAccessToken_findsTheUserByTheRefreshCookie() {
        // An expired access cookie leaves the request anonymous; the user's name is then "anonymousUser".
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        UUID userId = UUID.randomUUID();
        User user = User.builder().username("alice@example.com").build();
        user.setId(userId);
        Token row = Token.builder().token(TokenHasher.sha256Hex("the.refresh.token")).tokenType(TokenType.REFRESH)
                .user(user).build();
        when(tokenRepository.findByToken(TokenHasher.sha256Hex("the.refresh.token"))).thenReturn(Optional.of(row));

        authService.logout("the.refresh.token");

        verify(userRepository, never()).findLiveById(any());
        verify(tokenRepository).deleteAllByUserId(userId);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(userId));
        verifyNoInteractions(tokenBlocklist);
    }

    @Test
    void logout_withRedisDown_stillEndsEverySession() {
        String token = "current.access.token";
        UUID userId = signedIn(token).getId();
        when(jwtUtil.extractJti(token)).thenReturn("jti-current");
        when(jwtUtil.getRemainingTtlMillis(token)).thenReturn(840_000L);
        StringRedisTemplate redisDown = mock(StringRedisTemplate.class);
        when(redisDown.opsForValue()).thenThrow(new RedisConnectionFailureException("down"));
        ReflectionTestUtils.setField(authService, "tokenBlocklist",
                new TokenBlocklist(redisDown, new SimpleMeterRegistry()));

        authService.logout(null);

        verify(tokenRepository).deleteAllByUserId(userId);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(userId));
    }

    @Test
    void logout_withNoSessionAtAll_endsNothing_andDoesNotFail() {
        when(tokenRepository.findByToken(TokenHasher.sha256Hex("unknown.token"))).thenReturn(Optional.empty());

        assertThatCode(() -> authService.logout("unknown.token")).doesNotThrowAnyException();
        assertThatCode(() -> authService.logout(null)).doesNotThrowAnyException();

        verify(tokenRepository, never()).deleteAllByUserId(any());
        verifyNoInteractions(sessionRevoker, userRepository);
    }
}
