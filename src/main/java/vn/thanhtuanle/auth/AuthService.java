package vn.thanhtuanle.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import jakarta.transaction.Transactional;
import vn.thanhtuanle.auth.GoogleIdTokenVerifier.GoogleIdentity;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.auth.dto.IntrospectRequest;
import vn.thanhtuanle.auth.dto.IntrospectResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.Role;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.exception.UniqueUserConstraints;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.HandleAllocator;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserLockTimeoutException;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.UserRowLockImpl;
import vn.thanhtuanle.user.dto.UserResponse;
import vn.thanhtuanle.user.mapper.UserMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    /**
     * A refresh token presented again this soon after it was rotated is a concurrent request (several tabs
     * refreshing at once), not theft: it gets 200 and nothing new. Later it is reuse.
     */
    public static final Duration REUSE_GRACE = Duration.ofSeconds(10);

    /**
     * At most this many failed logins sleep their backoff at the same time. Beyond it a failure is answered at once (its
     * counters and locks still apply), so no burst can hold more than this slice of the worker threads.
     */
    static final int MAX_CONCURRENT_BACKOFFS = 32;
    private final Semaphore backoffPermits = new Semaphore(MAX_CONCURRENT_BACKOFFS);

    /** A Google sign-in whose new handle a concurrent sign-up took first tries this many more times. */
    static final int MAX_HANDLE_RETRIES = 2;

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
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final HandleAllocator handleAllocator;

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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Startup check. The id token's signature is not checked ({@link GoogleIdTokenVerifier}): TLS to Google's token
     * endpoint is what proves who issued it, so a token URI that is not https would accept anyone's token.
     */
    @PostConstruct
    void requireHttpsTokenUri() {
        if (!"https".equalsIgnoreCase(URI.create(tokenUri).getScheme())) {
            throw new IllegalStateException(
                    "spring.security.oauth2.client.provider.google.token-uri (GOOGLE_TOKEN_URI) must be an https URL");
        }
    }

    /**
     * Starts a Google sign-in: the authorization URL plus a fresh {@code state}, PKCE code verifier and nonce. The
     * caller parks the three in cookies only the callback receives. Scopes are the OIDC identity only; no
     * {@code access_type=offline}, because nothing here uses a Google refresh token.
     */
    public GoogleAuthorization getGoogleAuthUrl() {
        String state = randomUrlToken();
        String codeVerifier = randomUrlToken();
        String nonce = randomUrlToken();
        String url = authorizationUri + "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code&scope=openid%20email%20profile" +
                "&state=" + state +
                "&nonce=" + nonce +
                "&code_challenge=" + pkceS256Challenge(codeVerifier) +
                "&code_challenge_method=S256";
        return new GoogleAuthorization(url, state, codeVerifier, nonce);
    }

    /** 32 random bytes, base64url without padding: 43 URL-safe characters (also a valid PKCE verifier). */
    private static String randomUrlToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** RFC 7636 S256: base64url-nopad(SHA-256(ASCII(code_verifier))). */
    private static String pkceS256Challenge(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // Every Java platform must provide SHA-256 (MessageDigest javadoc).
            throw new IllegalStateException(e);
        }
    }

    /**
     * Completes a Google sign-in: exchanges the code (with its PKCE verifier) for Google's id token, which must carry
     * this attempt's nonce, and signs in the live account linked to that Google id ({@code sub}), whatever its email is
     * now. Failing that, the live account with the email (in any case): one already linked to another Google id is
     * refused; one with none is linked, if Google is authoritative for the address; with no account, one is created. A
     * Google id or email that only a soft-deleted account has is blocked.
     *
     * <p>An unverified email is refused first, before any account is looked at, even one the {@code sub} would find:
     * the spec orders that rule first, and the strict order is the simpler one.
     *
     * <p>Not {@code @Transactional}: the call to Google holds neither a transaction nor a pooled connection. The account
     * and token writes run in one short transaction, under the user's row lock, like every other token change. The
     * attempt is audited after that transaction ends, so the audit's own connection is never taken under the lock.
     */
    public AuthResponse authenticateGoogleUser(String code, String codeVerifier, String nonce, ClientMeta meta) {
        GoogleIdentity google = googleIdTokenVerifier.verify(exchangeCode(code, codeVerifier), nonce);

        // Anyone can put any address on a Google account; only a verified one says who owns it.
        if (!google.emailVerified()) {
            loginAttemptService.record(google.email(), meta, false, ErrorCode.GOOGLE_EMAIL_UNVERIFIED.name());
            throw new AppException(ErrorCode.GOOGLE_EMAIL_UNVERIFIED);
        }

        AuthResponse tokens;
        try {
            tokens = googleSession(google, meta);
        } catch (AppException e) {
            // The transaction has rolled back and released the row lock: the audit (REQUIRES_NEW) waits for a pooled
            // connection of its own, and must not keep the user locked while it does.
            loginAttemptService.record(google.email(), meta, false, e.getErrorCode().name());
            throw e;
        }

        loginAttemptService.record(google.email(), meta, true, null);
        return tokens;
    }

    /**
     * Finds the account and runs the sign-in's writes. When no account was found and a unique index on users refuses
     * the new one, an account may have been committed meanwhile (the same Google account's first sign-in from another
     * tab won the race): the account is looked up once more, and the sign-in goes to the one found. When the refusal is
     * the handle's ({@code USERNAME_EXISTED}: another sign-up took it first), the writes run again with the next free
     * handle, at most {@link #MAX_HANDLE_RETRIES} more times. Any other refusal stands.
     */
    private AuthResponse googleSession(GoogleIdentity google, ClientMeta meta) {
        GoogleMatch match = googleAccount(google);
        int handleRetries = 0;
        while (true) {
            GoogleMatch attempt = match;
            try {
                return inGoogleSessionTransaction(() -> startGoogleSession(attempt, google, meta));
            } catch (AppException e) {
                if (!UniqueUserConstraints.isConflict(e.getErrorCode())) {
                    throw e;
                }
                if (attempt.userId() == null) {
                    GoogleMatch again = googleAccount(google);
                    if (again.userId() != null) {
                        log.info("Google login: the new account conflicted with one committed meanwhile ({}); "
                                + "signing in to it", e.getErrorCode().name());
                        match = again;
                        continue;
                    }
                }
                if (e.getErrorCode() != ErrorCode.USERNAME_EXISTED || handleRetries == MAX_HANDLE_RETRIES) {
                    throw e;
                }
                handleRetries++;
                log.info("Google sign-up lost a handle race; trying the next free one");
            }
        }
    }

    /**
     * Runs a Google sign-in's writes in their transaction. A unique index on users that refuses them (two first sign-ins
     * for one new account racing, or a Google id linked meanwhile) is a refusal with its reason, like any other.
     */
    private AuthResponse inGoogleSessionTransaction(Supplier<AuthResponse> writes) {
        try {
            return transactionTemplate.execute(status -> writes.get());
        } catch (DataIntegrityViolationException e) {
            throw UniqueUserConstraints.toErrorCode(e).map(AppException::new).orElseThrow(() -> e);
        }
    }

    /** The account a Google identity signs in to: found by its Google id, by its email, or none (a new account). */
    private record GoogleMatch(UUID userId, boolean bySub) {
        static final GoogleMatch NONE = new GoogleMatch(null, false);
    }

    /**
     * Finds the account, outside the transaction (only its id is kept): the live account linked to the Google id
     * ({@code sub}, Google's stable identifier; OIDC Core 5.7), else the live account with the Google email in any case.
     * A soft-deleted account with that Google id or email blocks the sign-in, as it did before soft-deleted rows stopped
     * counting towards uniqueness: its owner does not get a fresh account by signing in again.
     */
    private GoogleMatch googleAccount(GoogleIdentity google) {
        Optional<UUID> bySub = userRepository.findLiveByGoogleId(google.sub()).map(User::getId);
        if (bySub.isPresent()) {
            return new GoogleMatch(bySub.get(), true);
        }
        Optional<UUID> byEmail = userRepository.findLiveByEmail(google.email()).map(User::getId);
        if (byEmail.isPresent()) {
            return new GoogleMatch(byEmail.get(), false);
        }
        if (userRepository.existsByGoogleIdOrEmailIgnoreCase(google.sub(), google.email())) {
            throw new AppException(ErrorCode.USER_BLOCKED);
        }
        return GoogleMatch.NONE;
    }

    /** The token request: the authorization code plus the PKCE verifier. Returns Google's id token. */
    private String exchangeCode(String code, String codeVerifier) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("code_verifier", codeVerifier);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ExchangeTokenResponse tokenResponse;
        try {
            ResponseEntity<ExchangeTokenResponse> response = restTemplate.postForEntity(tokenUri,
                    new HttpEntity<>(params, headers), ExchangeTokenResponse.class);
            tokenResponse = response.getBody();
        } catch (HttpClientErrorException e) {
            // Google refused the code (made up, expired, already used, another verifier): anyone can cause this from
            // the public callback, so what Google said, without a stack trace.
            log.warn("Google refused the authorization code: {} {}", e.getStatusCode().value(), googleError(e));
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        } catch (Exception e) {
            // Google could not be reached or answered with a server error, or the call timed out: ours to look at.
            log.error("Failed to exchange token with Google", e);
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
        if (tokenResponse == null) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
        return tokenResponse.getIdToken();
    }

    /** The {@code error} field of Google's refusal ({@code invalid_grant}, ...), in its loggable form. */
    private static String googleError(HttpClientErrorException e) {
        try {
            return OAuthErrors.loggable(JSON.readTree(e.getResponseBodyAsString()).path("error").asText(""));
        } catch (Exception notJson) {
            return "";
        }
    }

    /**
     * A Google sign-in's writes: link or create the account, then this login's tokens replace every earlier one. An
     * existing account is read again under its row lock, so the link decision and the writes see its current row, not
     * the copy read before the transaction.
     */
    private AuthResponse startGoogleSession(GoogleMatch match, GoogleIdentity google, ClientMeta meta) {
        User user = match.userId() == null ? newAccount(google)
                : match.bySub() ? accountLinkedTo(match.userId(), google)
                : accountWithEmail(match.userId(), google);

        // Only active accounts may log in (disabled/soft-deleted users are blocked).
        // Audited like the password flow (by the caller); NOT rate-limited — the OAuth code exchange is its own guard.
        if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
            throw new AppException(ErrorCode.USER_BLOCKED);
        }
        giveHandleIfEmailNamed(user);

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

    /**
     * An account that signed up with Google before handles existed has its email as its username (V8 renames those
     * that exist at deploy time; this catches any made meanwhile). It gets its handle now, before this login's tokens
     * are minted, so their {@code sub} is the handle. Flushed at once, so a unique index that refuses the handle does
     * so inside the transaction, and the sign-in retries with the next free one.
     */
    private void giveHandleIfEmailNamed(User user) {
        if (user.getUsername() == null || !user.getUsername().contains("@")) {
            return;
        }
        user.setUsername(handleAllocator.allocate(HandleAllocator.sourceOf(user.getEmail(), user.getName())));
        userRepository.saveAndFlush(user);
        log.info("Google login: user {} got its public handle in place of its email", user.getId());
    }

    /**
     * The account linked to the Google id, locked. Its email stays as it is, even when Google's has changed: the
     * account's own email may differ, and changing it could collide with another account's. The row as locked must
     * still be linked to that Google id: one unlinked since it was found is not that Google account's.
     */
    private User accountLinkedTo(UUID id, GoogleIdentity google) {
        User user = userRepository.lockById(id).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        if (!google.sub().equals(user.getGoogleId())) {
            log.warn("Google login refused: user {} changed its Google link while the login was finding it",
                    user.getId());
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }
        return user;
    }

    /**
     * The account with the Google email, locked. Linked to another Google id: refused. Linked to none: linked now, if
     * Google is authoritative for the address. The row as locked must still have that email: one changed since it was
     * found is not the account the email named.
     */
    private User accountWithEmail(UUID id, GoogleIdentity google) {
        User user = userRepository.lockById(id).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        if (!google.email().equalsIgnoreCase(user.getEmail())) {
            log.warn("Google login refused: user {} changed its email while the login was finding it", user.getId());
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }
        if (user.getGoogleId() == null) {
            if (!googleIsAuthoritativeFor(google)) {
                log.warn("Google login refused: user {} is not linked, and Google does not vouch for its address",
                        user.getId());
                throw new AppException(ErrorCode.GOOGLE_LINK_NOT_ALLOWED);
            }
            user.setGoogleId(google.sub());
            if (user.getAvatar() == null)
                user.setAvatar(google.picture());
        } else if (!user.getGoogleId().equals(google.sub())) {
            log.warn("Google login refused: user {} is linked to a different Google account", user.getId());
            throw new AppException(ErrorCode.GOOGLE_ACCOUNT_MISMATCH);
        }
        return user;
    }

    /**
     * Google is authoritative for an address only on gmail.com and for Workspace accounts ({@code hd}). Elsewhere,
     * {@code email_verified} may date from when the Google account was made, and the address may have changed hands
     * since, so it cannot hand over an existing account.
     */
    private static boolean googleIsAuthoritativeFor(GoogleIdentity google) {
        return google.email().toLowerCase(Locale.ROOT).endsWith("@gmail.com")
                || (google.hd() != null && !google.hd().isBlank());
    }

    private User newAccount(GoogleIdentity google) {
        var role = roleRepository.findByName(Role.USER.getValue())
                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));
        // Flushed now, so a unique index that refuses the new account does so here, inside the transaction.
        User user = userRepository.saveAndFlush(User.builder()
                .name(google.name())
                .username(handleAllocator.allocate(HandleAllocator.sourceOf(google.email(), google.name())))
                .email(google.email())
                .avatar(google.picture())
                .googleId(google.sub())
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>(Collections.singletonList(role)))
                .build());
        // No other transaction can see the row before this one commits, but its tokens follow the same rule as
        // everyone's: written under the user's row lock.
        userRepository.lockById(user.getId());
        return user;
    }

    /**
     * Username + password login. For password accounts (e.g. the seeded admin) — Google-only
     * users have no password and fall through to the same generic error, so this endpoint can't
     * be used to tell a real username from a wrong password. Mirrors the Google flow's token
     * bookkeeping; the caller sets the returned tokens as HttpOnly cookies.
     *
     * <p>The attempt takes its place in the limiter's counters before the password is checked, so a burst is refused
     * at once (429) beyond the pair's five and one probe, with no BCrypt. Only a credential outcome counts as a
     * failure; an attempt that ends without one hands its places back.
     *
     * <p>Deliberately not {@code @Transactional}: a failure sleeps the limiter's backoff (up to 4 s) before
     * answering, and must hold neither a transaction nor a pooled connection meanwhile, or a credential
     * spray would drain the pool and stall every other request. Only a success's writes run in a transaction.
     * The connection part also needs {@code spring.jpa.open-in-view: false} (application.yml).
     */
    public AuthResponse authenticateWithPassword(String username, String password, ClientMeta meta) {
        LoginRateLimiter.Attempt attempt = loginRateLimiter.reserve(username, meta);

        AuthResponse tokens;
        try {
            User user = userRepository.findByUsername(username)
                    .filter(u -> u.getPassword() != null && passwordEncoder.matches(password, u.getPassword()))
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

            if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
                throw new AppException(ErrorCode.USER_BLOCKED);
            }
            String verifiedHash = user.getPassword();
            tokens = transactionTemplate.execute(status -> startPasswordSession(user.getId(), verifiedHash, meta));
        } catch (RuntimeException e) {
            if (isCredentialFailure(e)) {
                Duration backoff = loginRateLimiter.recordFailure(attempt);
                try {
                    loginAttemptService.record(username, meta, false, ((AppException) e).getErrorCode().name());
                } finally {
                    // Whatever the audit does, the delay is not skipped.
                    backOff(backoff);
                }
            } else {
                // No verdict on the password (the account was busy past the lock timeout, or something broke): not a
                // failed attempt, so it hands its places back.
                loginRateLimiter.release(attempt);
            }
            throw e;
        }

        loginRateLimiter.recordSuccess(attempt);
        loginAttemptService.record(username, meta, true, null);

        log.info("Password login for user: {}", username);
        return tokens;
    }

    /** A wrong password, an unknown user, or a blocked account: the outcomes of checking a credential. */
    private static boolean isCredentialFailure(RuntimeException e) {
        return e instanceof AppException app
                && (app.getErrorCode() == ErrorCode.USER_NOT_EXISTED || app.getErrorCode() == ErrorCode.USER_BLOCKED);
    }

    /** Sleeps a failed login's delay, unless {@link #MAX_CONCURRENT_BACKOFFS} others already are. */
    private void backOff(Duration delay) {
        if (delay == null || delay.isZero() || delay.isNegative()) {
            return;
        }
        if (!backoffPermits.tryAcquire()) {
            log.debug("Every backoff permit is taken: answering a failed login without its delay");
            return;
        }
        try {
            sleeper.sleep(delay);
        } finally {
            backoffPermits.release();
        }
    }

    /**
     * A successful password login's writes: this login's tokens replace every earlier one. They go to the user's row as
     * locked now, not to the copy read before the password check, so a concurrent change to the user is not undone.
     *
     * <p>The check is repeated under the lock: if the row no longer holds the hash BCrypt matched ({@code verifiedHash}),
     * or is no longer active, a password change, reset or disable committed meanwhile and ended every session. Nothing
     * is written (the transaction rolls back) and the login fails like a wrong password, so it reveals nothing new.
     */
    private AuthResponse startPasswordSession(UUID userId, String verifiedHash, ClientMeta meta) {
        User user = userRepository.lockById(userId).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        if (!Objects.equals(user.getPassword(), verifiedHash)
                || !Objects.equals(user.getStatus(), CommonStatus.ACTIVE.getValue())) {
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        }
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

    /** Callers hold the user's row lock ({@link UserRepository#lockById}), so a concurrent rotation cannot slip by. */
    private void revokeAllUserTokens(User user) {
        tokenRepository.deleteAllByUserId(user.getId());
    }

    /**
     * Rotates the refresh token: the presented one is marked rotated and a new access and refresh token are issued.
     * Returns both tokens, or both {@code null} when a concurrent refresh already rotated this token (nothing issued).
     * A rotated token presented again after {@link #REUSE_GRACE} means it was copied: every session of the user ends.
     * The successor expires no later than the presented token, so a session ends one refresh TTL after its login.
     *
     * <p>{@code dontRollbackOn}: only the reuse branch relies on it, so that its deletes commit even though the
     * request answers 401. It applies to every AppException, though: one thrown after {@code markRotated} would commit
     * a rotation with no successor and sign the user out. Nothing after {@code markRotated} may throw one.
     * {@code rollbackOn} takes the lock timeout back out of it (the more specific rule wins): that transaction has
     * already failed in Postgres and cannot commit.
     */
    @Transactional(dontRollbackOn = AppException.class, rollbackOn = UserLockTimeoutException.class)
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
        // Serialise with every other token change of this user. A concurrent refresh that won meanwhile leaves this
        // one's markRotated at 0 below; a logout that won leaves no row for it to rotate. The status gate and the
        // minting use this row, read under the lock.
        User user = userRepository.lockById(stored.getUser().getId())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        LocalDateTime now = LocalDateTime.now(clock);
        if (stored.getRotatedAt() != null) {
            if (!now.isAfter(stored.getRotatedAt().plus(REUSE_GRACE))) {
                return AuthResponse.builder().build();
            }
            UUID uid = user.getId();
            tokenRepository.deleteAllByUserId(uid);
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(uid));
            log.warn("Refresh token reuse for user {}: every session ended", uid);
            throw new AppException(ErrorCode.REFRESH_TOKEN_REUSED);
        }

        // Same account-status gate as authenticateWithPassword: a disabled/blocked account
        // must not be able to keep renewing its access token via refresh.
        if (user.getStatus() == null || user.getStatus() != CommonStatus.ACTIVE.getValue()) {
            throw new AppException(ErrorCode.USER_BLOCKED);
        }

        // The session's end: the successor never outlives the token it replaces. Read before anything is written.
        Date sessionEnd = jwtUtil.extractExpiration(refreshToken);

        // Conditional on rotated_at still being null: of two refreshes racing with the same token, one wins.
        if (tokenRepository.markRotated(stored.getId(), now) == 0) {
            return AuthResponse.builder().build();
        }

        String newAccessToken = jwtUtil.generateToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user, sessionEnd);
        // One ACCESS row per live session: at a 15-minute TTL, appending a row per
        // refresh would add ~96 rows/user/day that nothing cleans up until the next login.
        tokenRepository.deleteAllByUserIdAndTokenType(user.getId(), TokenType.ACCESS);
        savedUserToken(user, newAccessToken, TokenType.ACCESS, meta);
        savedUserToken(user, newRefreshToken, TokenType.REFRESH, meta);
        // A rotated row is kept only to recognise reuse, which is moot once the token it held has expired.
        tokenRepository.deleteRotatedBefore(user.getId(), now.minus(Duration.ofMillis(refreshTokenTtlMillis)));
        log.info("Rotated the refresh token for user: {}", user.getUsername());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    /** The caller's profile: the live account its access token names by id ({@link Caller}), never by username. */
    public UserResponse me() {
        log.info("Fetching current user information");
        User user = Caller.id().flatMap(userRepository::findLiveById)
                .orElseThrow(() -> {
                    log.warn("No live user for the access token's uid");
                    return new AppException(ErrorCode.USER_NOT_EXISTED);
                });

        log.info("User information retrieved for username: {}", user.getUsername());
        return userMapper.toResponse(user);
    }

    /**
     * Ends every session of the caller. The caller is found from a verified access token (by its {@code uid}, see
     * {@link Caller}) or, when that has expired (the common case with 15-minute tokens: the request is then anonymous),
     * from the refresh cookie. With neither there is nothing to end, and the caller still clears the cookies.
     *
     * <p>Not {@code @Transactional}: the sessions end in a transaction of their own, which is tried once more when the
     * user's row stays locked past the lock timeout. The caller clears the cookies whatever this answers, so giving up
     * at once would leave every other session alive with nothing left in the browser to retry from. Each try waits at
     * most {@link UserRowLockImpl#LOGOUT_LOCK_TIMEOUT} (3 s) for the row, so the whole call takes at most about 6.5 s,
     * under the portal's 10 s request timeout.
     */
    public void logout(String refreshToken) {
        log.info("Logout request received");
        Optional<UUID> userId = Optional.empty();
        // Never by an anonymous request's name: that is "anonymousUser", not a user.
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwtAuthentication) {
            // Revoke the access token the caller is holding right now: park its jti in Redis until it
            // would have expired, so the gateway strips it from any further request (the DB revoke below
            // only invalidates refresh tokens — access tokens are verified without the DB).
            String accessToken = jwtAuthentication.getToken().getTokenValue();
            tokenBlocklist.block(jwtUtil.extractJti(accessToken), jwtUtil.getRemainingTtlMillis(accessToken));
            userId = Caller.id().flatMap(userRepository::findLiveById).map(User::getId);
        }
        if (userId.isEmpty() && refreshToken != null && !refreshToken.isBlank()) {
            userId = tokenRepository.findByToken(TokenHasher.sha256Hex(refreshToken)).map(row -> row.getUser().getId());
        }
        if (userId.isEmpty()) {
            log.info("Logout without a session: nothing to end");
            return;
        }

        UUID uid = userId.get();
        try {
            endEverySession(uid);
        } catch (UserLockTimeoutException busy) {
            log.warn("Logout of user {} waited too long for the user's row; trying once more", uid);
            endEverySession(uid);
        }
        log.info("User logged out successfully");
    }

    /**
     * Under the user's row lock (a short wait, {@link UserRowLockImpl#LOGOUT_LOCK_TIMEOUT}), in a transaction of its
     * own: every token row goes, every access token is revoked.
     */
    private void endEverySession(UUID uid) {
        transactionTemplate.executeWithoutResult(status -> {
            userRepository.lockById(uid, UserRowLockImpl.LOGOUT_LOCK_TIMEOUT);
            tokenRepository.deleteAllByUserId(uid);
            // Every device's access token, not only the caller's: the gateway strips tokens issued before the cutoff.
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(uid));
        });
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
