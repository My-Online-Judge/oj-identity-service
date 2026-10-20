package vn.thanhtuanle.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceGoogleTest {

    private static final String CLIENT_ID = "client-123.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "fake-secret";
    private static final String REDIRECT_URI = "https://oj.example/api/v1/auth/outbound/google/callback";
    private static final String AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/auth";
    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final Instant NOW = Instant.parse("2026-10-20T05:00:00Z");
    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "browser/1.0");
    private static final String CODE = "the-code";
    private static final String VERIFIER = "the-verifier";
    private static final String NONCE = "the-nonce";
    private static final String SUB = "google-sub-1";
    private static final String EMAIL = "alice@example.com";

    @Mock UserRepository userRepository;
    @Mock JwtUtil jwtUtil;
    @Mock TokenRepository tokenRepository;
    @Mock RoleRepository roleRepository;
    @Mock RestTemplate restTemplate;
    @Mock LoginAttemptService loginAttemptService;

    @Spy Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    @Spy GoogleIdTokenVerifier googleIdTokenVerifier = new GoogleIdTokenVerifier(CLIENT_ID, clock);

    private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
    @Spy TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);

    @InjectMocks AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "clientId", CLIENT_ID);
        ReflectionTestUtils.setField(authService, "clientSecret", CLIENT_SECRET);
        ReflectionTestUtils.setField(authService, "redirectUri", REDIRECT_URI);
        ReflectionTestUtils.setField(authService, "authorizationUri", AUTHORIZATION_URI);
        ReflectionTestUtils.setField(authService, "tokenUri", TOKEN_URI);
    }

    /** The id token Google's token endpoint returns for this login. */
    private static String idToken(boolean emailVerified) {
        return new PlainJWT(new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com")
                .audience(CLIENT_ID)
                .subject(SUB)
                .expirationTime(Date.from(NOW.plusSeconds(3600)))
                .claim("nonce", NONCE)
                .claim("email", EMAIL)
                .claim("email_verified", emailVerified)
                .claim("name", "Alice")
                .claim("picture", "https://example.com/alice.png")
                .build()).serialize();
    }

    private void googleAnswers(String idToken) {
        when(restTemplate.postForEntity(eq(TOKEN_URI), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(ExchangeTokenResponse.builder()
                        .accessToken("google-access").idToken(idToken).build()));
    }

    private User account(String googleId) {
        User u = User.builder().username(EMAIL).email(EMAIL).googleId(googleId)
                .status(CommonStatus.ACTIVE.getValue()).build();
        u.setId(UUID.randomUUID());
        return u;
    }

    /** An existing account with this email; the session's writes find it again under the row lock. */
    private User existingAccount(String googleId) {
        User u = account(googleId);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(u));
        when(userRepository.lockById(u.getId())).thenReturn(Optional.of(u));
        return u;
    }

    private void mints(User u) {
        when(jwtUtil.generateToken(u)).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(u)).thenReturn("RT");
    }

    private static String base64UrlSha256(String ascii) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(ascii.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @Test
    void authUrl_hasPkceS256AndNonce_andNoOfflineAccess() throws Exception {
        GoogleAuthorization auth = authService.getGoogleAuthUrl();

        assertThat(auth.url()).startsWith(AUTHORIZATION_URI + "?");
        MultiValueMap<String, String> query = UriComponentsBuilder.fromUriString(auth.url()).build().getQueryParams();
        assertThat(query.toSingleValueMap()).containsOnlyKeys("client_id", "redirect_uri", "response_type", "scope",
                "state", "nonce", "code_challenge", "code_challenge_method");
        assertThat(query.getFirst("client_id")).isEqualTo(CLIENT_ID);
        assertThat(query.getFirst("redirect_uri")).isEqualTo(REDIRECT_URI);
        assertThat(query.getFirst("response_type")).isEqualTo("code");
        assertThat(query.getFirst("scope")).isEqualTo("openid%20email%20profile");
        assertThat(query.getFirst("state")).isEqualTo(auth.state());
        assertThat(query.getFirst("nonce")).isEqualTo(auth.nonce());
        assertThat(query.getFirst("code_challenge_method")).isEqualTo("S256");
        assertThat(query.getFirst("code_challenge")).isEqualTo(base64UrlSha256(auth.codeVerifier()));
        // No refresh token from Google: nothing here ever uses one.
        assertThat(auth.url()).doesNotContain("access_type");

        // Each is 32 random bytes, base64url without padding (43 characters, a valid PKCE verifier).
        for (String value : new String[] {auth.state(), auth.codeVerifier(), auth.nonce()}) {
            assertThat(value).matches("[A-Za-z0-9_-]{43}");
            assertThat(Base64.getUrlDecoder().decode(value)).hasSize(32);
        }
        assertThat(auth.state()).isNotEqualTo(auth.codeVerifier()).isNotEqualTo(auth.nonce());
        assertThat(authService.getGoogleAuthUrl().codeVerifier()).isNotEqualTo(auth.codeVerifier());
    }

    @Test
    @SuppressWarnings("unchecked")
    void codeExchange_sendsTheVerifier() {
        googleAnswers(idToken(true));
        mints(existingAccount(SUB));

        authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> request = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForEntity(eq(TOKEN_URI), request.capture(), eq(ExchangeTokenResponse.class));
        MultiValueMap<String, String> form = request.getValue().getBody();
        assertThat(form.toSingleValueMap()).containsExactlyInAnyOrderEntriesOf(java.util.Map.of(
                "code", CODE,
                "code_verifier", VERIFIER,
                "client_id", CLIENT_ID,
                "client_secret", CLIENT_SECRET,
                "redirect_uri", REDIRECT_URI,
                "grant_type", "authorization_code"));
        // The identity comes from the id token: no userinfo call.
        verifyNoMoreInteractions(restTemplate);
    }

    @Test
    void tokenResponse_bindsGooglesIdTokenField() throws Exception {
        ExchangeTokenResponse parsed = new ObjectMapper().readValue(
                "{\"access_token\":\"a\",\"id_token\":\"header.payload.\",\"expires_in\":3599}",
                ExchangeTokenResponse.class);

        assertThat(parsed.getIdToken()).isEqualTo("header.payload.");
    }

    @Test
    void unverifiedEmail_is403_andTouchesNoUser() {
        googleAnswers(idToken(false));

        assertThatThrownBy(() -> authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META))
                .isInstanceOfSatisfying(AppException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_EMAIL_UNVERIFIED);
                    assertThat(e.getErrorCode().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                });
        verifyNoInteractions(userRepository, roleRepository, tokenRepository, jwtUtil, transactionManager);
        verify(loginAttemptService).record(EMAIL, META, false, "GOOGLE_EMAIL_UNVERIFIED");
    }

    @Test
    void otherGoogleId_is403Mismatch() {
        googleAnswers(idToken(true));
        User u = existingAccount("google-sub-OTHER");

        assertThatThrownBy(() -> authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META))
                .isInstanceOfSatisfying(AppException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ACCOUNT_MISMATCH);
                    assertThat(e.getErrorCode().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                });
        assertThat(u.getGoogleId()).isEqualTo("google-sub-OTHER");
        verify(userRepository, never()).save(any());
        verifyNoInteractions(tokenRepository, jwtUtil);
        // Audited once the transaction has rolled back, i.e. with the user's row lock released.
        InOrder order = inOrder(transactionManager, loginAttemptService);
        order.verify(transactionManager).rollback(any());
        order.verify(loginAttemptService).record(EMAIL, META, false, "GOOGLE_ACCOUNT_MISMATCH");
    }

    @Test
    void accountWithoutGoogleId_isLinked() {
        googleAnswers(idToken(true));
        User u = existingAccount(null);
        mints(u);

        AuthResponse res = authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META);

        assertThat(res.getAccessToken()).isEqualTo("AT");
        assertThat(res.getRefreshToken()).isEqualTo("RT");
        assertThat(u.getGoogleId()).isEqualTo(SUB);
        assertThat(u.getAvatar()).isEqualTo("https://example.com/alice.png");
        verify(userRepository).save(u);
        verify(loginAttemptService).record(EMAIL, META, true, null);
    }

    @Test
    void newVerifiedUser_isCreated() {
        googleAnswers(idToken(true));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        Role userRole = Role.builder().name("USER").build();
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        UUID newId = UUID.randomUUID();
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            if (saved.getId() == null) {
                saved.setId(newId);
            }
            return saved;
        });
        ArgumentCaptor<User> created = ArgumentCaptor.forClass(User.class);
        when(jwtUtil.generateToken(created.capture())).thenReturn("AT");
        when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn("RT");

        AuthResponse res = authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META);

        assertThat(res.getAccessToken()).isEqualTo("AT");
        User user = created.getValue();
        assertThat(user.getId()).isEqualTo(newId);
        assertThat(user.getEmail()).isEqualTo(EMAIL);
        assertThat(user.getUsername()).isEqualTo(EMAIL);
        assertThat(user.getGoogleId()).isEqualTo(SUB);
        assertThat(user.getName()).isEqualTo("Alice");
        assertThat(user.getAvatar()).isEqualTo("https://example.com/alice.png");
        assertThat(user.getStatus()).isEqualTo(CommonStatus.ACTIVE.getValue());
        assertThat(user.getRoles()).containsExactly(userRole);
        // The new row is locked like any other before its tokens are written.
        InOrder order = inOrder(userRepository, tokenRepository);
        order.verify(userRepository).lockById(newId);
        order.verify(tokenRepository).deleteAllByUserId(newId);
    }

    @Test
    void googleLogin_locksTheUserRowBeforeReplacingItsTokens() {
        googleAnswers(idToken(true));
        User u = existingAccount(null);
        mints(u);

        authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META);

        // Serialises this login with any refresh, logout or other login of the same user: the link and the token
        // replacement run in one transaction, under the user's row lock, on the row as locked (not the copy read
        // before it). The call to Google holds no transaction.
        InOrder order = inOrder(restTemplate, userRepository, transactionManager, tokenRepository);
        order.verify(restTemplate).postForEntity(eq(TOKEN_URI), any(HttpEntity.class), eq(ExchangeTokenResponse.class));
        order.verify(userRepository).findByEmail(EMAIL);
        order.verify(transactionManager).getTransaction(any());
        order.verify(userRepository).lockById(u.getId());
        order.verify(tokenRepository).deleteAllByUserId(u.getId());
        order.verify(tokenRepository, times(2)).save(any(Token.class));
        order.verify(userRepository).save(u);
        order.verify(transactionManager).commit(any());
        // The audit's own connection is taken after the commit has released the lock.
        InOrder audit = inOrder(transactionManager, loginAttemptService);
        audit.verify(transactionManager).commit(any());
        audit.verify(loginAttemptService).record(EMAIL, META, true, null);
    }

    @Test
    void blockedAccount_isRefused_andMintsNothing() {
        googleAnswers(idToken(true));
        User u = existingAccount(SUB);
        u.setStatus(CommonStatus.INACTIVE.getValue());

        assertThatThrownBy(() -> authService.authenticateGoogleUser(CODE, VERIFIER, NONCE, META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USER_BLOCKED));
        verifyNoInteractions(tokenRepository, jwtUtil);
        InOrder order = inOrder(transactionManager, loginAttemptService);
        order.verify(transactionManager).rollback(any());
        order.verify(loginAttemptService).record(EMAIL, META, false, "USER_BLOCKED");
    }

    @Test
    void aTokenForAnotherNonce_isRefused_beforeAnyAccountIsTouched() {
        googleAnswers(idToken(true));

        assertThatThrownBy(() -> authService.authenticateGoogleUser(CODE, VERIFIER, "another-nonce", META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ID_TOKEN_INVALID));
        verifyNoInteractions(userRepository, tokenRepository, transactionManager);
    }
}
