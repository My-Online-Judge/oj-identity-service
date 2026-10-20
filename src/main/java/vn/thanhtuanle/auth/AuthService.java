package vn.thanhtuanle.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import jakarta.transaction.Transactional;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.auth.dto.FullUserInfo;
import vn.thanhtuanle.auth.dto.IntrospectRequest;
import vn.thanhtuanle.auth.dto.IntrospectResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.Role;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.dto.UserResponse;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    /**
     * A refresh token presented again this soon after it was rotated is a concurrent request (several tabs
     * refreshing at once), not theft: it gets 200 and nothing new. Later it is reuse.
     */
    public static final Duration REUSE_GRACE = Duration.ofSeconds(10);

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final TokenRepository tokenRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final RestTemplate restTemplate;
    private final TokenBlocklist tokenBlocklist;
    private final PasswordEncoder passwordEncoder;
    private final LoginRateLimiter loginRateLimiter;
    private final LoginAttemptService loginAttemptService;
    private final SessionRevoker sessionRevoker;
    private final Clock clock;
    private final Sleeper sleeper;
    private final TransactionTemplate transactionTemplate;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshTokenTtlMillis;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.provider.google.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String userInfoUri;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Build the Google authorization URL together with a fresh, unguessable {@code state}.
     * The frontend stores the state before redirecting and verifies it on the callback,
     * which defends the login flow against CSRF / authorization-code injection.
     */
    public Map<String, String> getGoogleAuthUrl() {
        String state = generateState();
        String url = authorizationUri + "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code&scope=email%20profile%20openid&access_type=offline" +
                "&state=" + state;
        return Map.of("url", url, "state", state);
    }

    private String generateState() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Transactional
    public AuthResponse authenticateGoogleUser(String code, ClientMeta meta) {
        // 1. Exchange code for tokens
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ExchangeTokenResponse tokenResponse;
        try {
            ResponseEntity<ExchangeTokenResponse> response = restTemplate.postForEntity(tokenUri, request,
                    ExchangeTokenResponse.class);
            tokenResponse = response.getBody();
        } catch (Exception e) {
            log.error("Failed to exchange token with Google", e);
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        // 2. Get User Info
        HttpHeaders userInfoHeaders = new HttpHeaders();
        userInfoHeaders.setBearerAuth(tokenResponse.getAccessToken());
        HttpEntity<String> userInfoRequest = new HttpEntity<>(userInfoHeaders);

        FullUserInfo googleUser;
        try {
            ResponseEntity<FullUserInfo> userInfoResponse = restTemplate.exchange(userInfoUri, HttpMethod.GET,
                    userInfoRequest, FullUserInfo.class);
            googleUser = userInfoResponse.getBody();
        } catch (Exception e) {
            log.error("Failed to get user info from Google", e);
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        if (googleUser == null) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        // 3. Find or Create User
        User user = userRepository.findByEmail(googleUser.getEmail()).orElseGet(() -> {
            var role = roleRepository.findByName(Role.USER.getValue())
                    .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

            return userRepository.save(User.builder()
                    .name(googleUser.getName())
                    .username(googleUser.getEmail())
                    .email(googleUser.getEmail())
                    .avatar(googleUser.getPicture())
                    .googleId(googleUser.getSub())
                    .status(CommonStatus.ACTIVE.getValue())
                    .roles(new HashSet<>(Collections.singletonList(role)))
                    .build());
        });

        // Update info if needed
        if (user.getGoogleId() == null) {
            user.setGoogleId(googleUser.getSub());
            if (user.getAvatar() == null)
                user.setAvatar(googleUser.getPicture());
            userRepository.save(user);
        }

        // Only active accounts may log in (disabled/soft-deleted users are blocked).
        // Audited like the password flow; NOT rate-limited — the OAuth code exchange is its own guard.
        if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
            loginAttemptService.record(user.getEmail(), meta, false, ErrorCode.USER_BLOCKED.name());
            throw new AppException(ErrorCode.USER_BLOCKED);
        }

        // 4. Generate Tokens
        var jwtToken = jwtUtil.generateToken(user);
        var refreshToken = jwtUtil.generateRefreshToken(user);

        revokeAllUserTokens(user);
        savedUserToken(user, jwtToken, TokenType.ACCESS, meta);
        savedUserToken(user, refreshToken, TokenType.REFRESH, meta);

        user.setLastLogin(LocalDateTime.now());
        user.setLastLoginIp(meta.ip());
        user.setLastLoginDeviceHash(meta.deviceHash());
        userRepository.save(user);

        loginAttemptService.record(user.getEmail(), meta, true, null);

        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Username + password login. For password accounts (e.g. the seeded admin) — Google-only
     * users have no password and fall through to the same generic error, so this endpoint can't
     * be used to tell a real username from a wrong password. Mirrors the Google flow's token
     * bookkeeping; the caller sets the returned tokens as HttpOnly cookies.
     *
     * <p>Deliberately not {@code @Transactional}: a failure sleeps the limiter's backoff (up to 8 s) before
     * answering, and must hold neither a transaction nor a pooled connection meanwhile, or a credential
     * spray would drain the pool and stall every other request. Only a success's writes run in a transaction.
     * The connection part also needs {@code spring.jpa.open-in-view: false} (application.yml).
     */
    public AuthResponse authenticateWithPassword(String username, String password, ClientMeta meta) {
        loginRateLimiter.assertAllowed(username, meta);

        User user;
        try {
            user = userRepository.findByUsername(username)
                    .filter(u -> u.getPassword() != null && passwordEncoder.matches(password, u.getPassword()))
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

            if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
                throw new AppException(ErrorCode.USER_BLOCKED);
            }
        } catch (AppException e) {
            Duration backoff = loginRateLimiter.recordFailure(username, meta);
            loginAttemptService.record(username, meta, false, e.getErrorCode().name());
            sleeper.sleep(backoff);
            throw e;
        }

        AuthResponse tokens = transactionTemplate.execute(status -> startPasswordSession(user, meta));

        loginRateLimiter.clear(username, meta);
        loginAttemptService.record(username, meta, true, null);

        log.info("Password login for user: {}", username);
        return tokens;
    }

    /** A successful password login's writes: this login's tokens replace every earlier one. */
    private AuthResponse startPasswordSession(User user, ClientMeta meta) {
        String accessToken = jwtUtil.generateToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        revokeAllUserTokens(user);
        savedUserToken(user, accessToken, TokenType.ACCESS, meta);
        savedUserToken(user, refreshToken, TokenType.REFRESH, meta);

        user.setLastLogin(LocalDateTime.now());
        user.setLastLoginIp(meta.ip());
        user.setLastLoginDeviceHash(meta.deviceHash());
        userRepository.save(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void savedUserToken(User user, String jwtToken, TokenType tokenType, ClientMeta meta) {
        var token = Token.builder()
                .user(user)
                .token(TokenHasher.sha256Hex(jwtToken))
                .tokenType(tokenType)
                .expired(false)
                .revoked(false)
                .ip(meta.ip())
                .deviceHash(meta.deviceHash())
                .userAgent(meta.userAgent())
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        tokenRepository.deleteAllByUserId(user.getId());
    }

    /**
     * Rotates the refresh token: the presented one is marked rotated and a new access and refresh token are issued.
     * Returns both tokens, or both {@code null} when a concurrent refresh already rotated this token (nothing issued).
     * A rotated token presented again after {@link #REUSE_GRACE} means it was copied: every session of the user ends.
     * Those deletes must commit even though the request answers 401, hence {@code dontRollbackOn}.
     */
    @Transactional(dontRollbackOn = AppException.class)
    public AuthResponse refreshAccessToken(String refreshToken, ClientMeta meta) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }
        try {
            if (jwtUtil.isTokenExpired(refreshToken)) {
                throw new AppException(ErrorCode.INVALID_CREDENTIALS);
            }
        } catch (AppException e) {
            throw e;
        } catch (Exception e) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }

        var stored = tokenRepository.findByToken(TokenHasher.sha256Hex(refreshToken))
                .orElseThrow(() -> new AppException(ErrorCode.INVALID_CREDENTIALS));
        if (stored.isRevoked() || stored.isExpired() || stored.getTokenType() != TokenType.REFRESH) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }

        LocalDateTime now = LocalDateTime.now(clock);
        if (stored.getRotatedAt() != null) {
            if (!now.isAfter(stored.getRotatedAt().plus(REUSE_GRACE))) {
                return AuthResponse.builder().build();
            }
            UUID uid = stored.getUser().getId();
            tokenRepository.deleteAllByUserId(uid);
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(uid));
            log.warn("Refresh token reuse for user {}: every session ended", uid);
            throw new AppException(ErrorCode.REFRESH_TOKEN_REUSED);
        }

        String username = jwtUtil.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Same account-status gate as authenticateWithPassword: a disabled/blocked account
        // must not be able to keep renewing its access token via refresh.
        if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
            throw new AppException(ErrorCode.USER_BLOCKED);
        }

        // Conditional on rotated_at still being null: of two refreshes racing with the same token, one wins.
        if (tokenRepository.markRotated(stored.getId(), now) == 0) {
            return AuthResponse.builder().build();
        }

        String newAccessToken = jwtUtil.generateToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        // One ACCESS row per live session: at a 15-minute TTL, appending a row per
        // refresh would add ~96 rows/user/day that nothing cleans up until the next login.
        tokenRepository.deleteAllByUserIdAndTokenType(user.getId(), TokenType.ACCESS);
        savedUserToken(user, newAccessToken, TokenType.ACCESS, meta);
        savedUserToken(user, newRefreshToken, TokenType.REFRESH, meta);
        // A rotated row is kept only to recognise reuse, which is moot once the token it held has expired.
        tokenRepository.deleteRotatedBefore(user.getId(), now.minus(Duration.ofMillis(refreshTokenTtlMillis)));
        log.info("Rotated the refresh token for user: {}", username);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    public UserResponse me() {
        log.info("Fetching current user information");
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return new AppException(ErrorCode.USER_NOT_EXISTED);
                });

        log.info("User information retrieved for username: {}", username);
        return userMapper.toResponse(user);
    }

    @Transactional
    public void logout() {
        log.info("Logout request received");
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return new AppException(ErrorCode.USER_NOT_EXISTED);
                });

        // Revoke the access token the caller is holding right now: park its jti in Redis until it
        // would have expired, so the gateway strips it from any further request (the DB revoke below
        // only invalidates refresh tokens — access tokens are verified without the DB).
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            String accessToken = jwtAuthentication.getToken().getTokenValue();
            tokenBlocklist.block(jwtUtil.extractJti(accessToken), jwtUtil.getRemainingTtlMillis(accessToken));
        }

        revokeAllUserTokens(user);
        // Every device's access token, not only the caller's: the gateway strips tokens issued before the cutoff.
        sessionRevoker.revokeAccessTokensAfterCommit(List.of(user.getId()));
        log.info("User logged out successfully");
    }

    public IntrospectResponse introspect(IntrospectRequest request) {
        var token = request.getToken();
        boolean isValid = true;

        try {
            if (jwtUtil.isTokenExpired(token))
                isValid = false;
        } catch (Exception e) {
            isValid = false;
        }

        if (isValid) {
            var storedToken = tokenRepository.findByToken(TokenHasher.sha256Hex(token))
                    .orElse(null);
            if (storedToken == null || storedToken.isRevoked() || storedToken.isExpired()
                    || !storedToken.getTokenType().equals(request.getTokenType())) {
                isValid = false;
            }
        }

        return IntrospectResponse.builder()
                .valid(isValid)
                .build();
    }
}
