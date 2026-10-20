package vn.thanhtuanle.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.IntrospectRequest;
import vn.thanhtuanle.auth.dto.IntrospectResponse;
import vn.thanhtuanle.auth.dto.LoginRequest;
import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.user.dto.UserResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping(Routes.AUTH)
@RequiredArgsConstructor
@Tag(name = "Auth Controller")
@Slf4j
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE = AuthCookies.REFRESH_TOKEN_COOKIE;
    private static final String OAUTH_STATE_COOKIE = "oauthState";
    private static final String OAUTH_VERIFIER_COOKIE = "oauthVerifier";
    private static final String OAUTH_NONCE_COOKIE = "oauthNonce";
    private static final String GOOGLE_OUTBOUND = "/outbound/google";
    /** The outbound call and its callback; nothing else ever receives the OAuth cookies. The edge forwards it as is. */
    private static final String OAUTH_COOKIE_PATH = Routes.AUTH + GOOGLE_OUTBOUND;
    private static final int REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60; // 7 days
    private static final int OAUTH_COOKIE_MAX_AGE = 5 * 60; // one login round-trip

    /** Where earlier versions set the state cookie. */
    private static final String LEGACY_OAUTH_STATE_PATH = "/";

    private final AuthService authService;
    private final AuthCookies authCookies;

    /**
     * Frontend origin the browser is sent back to once Google redirects here.
     * Because the redirect_uri registered with Google points at this API, the SPA can
     * move between ports/hosts by changing only this value — no Google Console edit.
     */
    @Value("${app.base-url:http://localhost:5173}")
    private String appBaseUrl;

    /**
     * The access token's lifetime ({@code JWT_ACCESS_TOKEN_EXPIRATION}). Its cookie lives exactly as long, so the
     * browser stops sending a token that can only be refused.
     */
    @Value("${application.security.jwt.expiration}")
    private long accessTokenTtlMillis;

    @Operation(summary = "Get Google Auth URL", description = "Get URL to redirect user to Google Login")
    @GetMapping(GOOGLE_OUTBOUND)
    public ApiResponse<Map<String, String>> getGoogleAuthUrl(HttpServletResponse response) {
        GoogleAuthorization auth = authService.getGoogleAuthUrl();
        // Google redirects straight back to this API, so the SPA never sees these. Park them in short-lived HttpOnly
        // cookies for the callback: the state (CSRF), the PKCE verifier and the nonce the id token must carry.
        writeOAuthCookie(response, OAUTH_STATE_COOKIE, auth.state(), OAUTH_COOKIE_MAX_AGE);
        writeOAuthCookie(response, OAUTH_VERIFIER_COOKIE, auth.codeVerifier(), OAUTH_COOKIE_MAX_AGE);
        writeOAuthCookie(response, OAUTH_NONCE_COOKIE, auth.nonce(), OAUTH_COOKIE_MAX_AGE);
        return ApiResponse.success(Map.of("url", auth.url()));
    }

    @Operation(summary = "Google OAuth callback", description = "Google redirects the browser here; exchanges the code, sets auth cookies, then returns the browser to the app")
    @GetMapping(GOOGLE_OUTBOUND + "/callback")
    public void googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @CookieValue(value = OAUTH_STATE_COOKIE, required = false) String expectedState,
            @CookieValue(value = OAUTH_VERIFIER_COOKIE, required = false) String codeVerifier,
            @CookieValue(value = OAUTH_NONCE_COOKIE, required = false) String nonce,
            HttpServletRequest httpRequest,
            HttpServletResponse response) throws IOException {
        // One-shot: always burn all three, whatever happens below.
        writeOAuthCookie(response, OAUTH_STATE_COOKIE, null, 0);
        writeOAuthCookie(response, OAUTH_VERIFIER_COOKIE, null, 0);
        writeOAuthCookie(response, OAUTH_NONCE_COOKIE, null, 0);
        // And the state cookie earlier versions left at Path=/ (harmless, but it would linger for its 5 minutes).
        authCookies.writeOAuth(response, OAUTH_STATE_COOKIE, null, 0, LEGACY_OAUTH_STATE_PATH);

        boolean stateMatched = statesMatch(state, expectedState);
        if (error != null || code == null || codeVerifier == null || nonce == null || !stateMatched) {
            // The error parameter is anyone's input: only its error-code-shaped start reaches the log.
            log.warn("Google callback rejected (error={}, hasCode={}, stateMatched={}, hasVerifier={}, hasNonce={})",
                    OAuthErrors.loggable(error), code != null, stateMatched, codeVerifier != null, nonce != null);
            response.sendRedirect(appBaseUrl + "/problems?login=failed");
            return;
        }

        try {
            AuthResponse auth = authService.authenticateGoogleUser(code, codeVerifier, nonce,
                    ClientMeta.from(httpRequest));
            writeSession(response, auth);
            response.sendRedirect(appBaseUrl + "/problems?login=ok");
        } catch (AppException e) {
            // A refusal with a reason (unverified email, another Google account, ...): the code name only.
            log.warn("Google login refused: {}", e.getErrorCode().name());
            response.sendRedirect(appBaseUrl + "/problems?login=failed&reason=" + e.getErrorCode().name());
        } catch (Exception e) {
            log.warn("Google login failed while exchanging the authorization code", e);
            response.sendRedirect(appBaseUrl + "/problems?login=failed");
        }
    }

    /** Constant-time compare so the state check can't be probed by timing. */
    private boolean statesMatch(String state, String expected) {
        return state != null && expected != null && MessageDigest.isEqual(
                state.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }

    @Operation(summary = "Login with username & password",
            description = "Authenticates a password account (e.g. the seeded admin) and sets HttpOnly auth cookies")
    @PostMapping("/login")
    public ApiResponse<Void> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest,
            HttpServletResponse response) {
        AuthResponse auth = authService.authenticateWithPassword(
                request.getUsername(), request.getPassword(), ClientMeta.from(httpRequest));
        writeSession(response, auth);
        return ApiResponse.success();
    }

    @Operation(summary = "Logout", description = "End every session of the user and clear cookies")
    @PostMapping("/logout")
    public ApiResponse<Void> logout(
            @CookieValue(value = REFRESH_TOKEN_COOKIE, required = false) String refreshCookie,
            HttpServletResponse response) {
        try {
            authService.logout(refreshCookie);
        } finally {
            // Whatever happened above: a refresh cookie left in the browser would sign the user straight back in.
            authCookies.clearSession(response);
        }
        return ApiResponse.success();
    }

    @Operation(summary = "Introspect Token", description = "Check if token is valid")
    @PostMapping("/introspect")
    public ApiResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request) {
        return ApiResponse.success(authService.introspect(request));
    }

    @Operation(summary = "Refresh access token", description = "Exchange a valid refresh token for a new access and refresh token, set as HttpOnly cookies")
    @PostMapping("/refresh")
    public ApiResponse<Void> refresh(
            @CookieValue(value = REFRESH_TOKEN_COOKIE, required = false) String refreshCookie,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        // The cookie is the only source. A client sending the token in the body would never see the rotated
        // cookie, and its second refresh would present a used token: reuse, every session ended.
        var authResponse = authService.refreshAccessToken(refreshCookie, ClientMeta.from(httpRequest));
        // No tokens: a concurrent request (another tab) rotated this refresh token a moment ago and its
        // response carries the new cookies, so this one leaves the browser's cookies alone.
        if (authResponse.getAccessToken() != null) {
            writeSession(response, authResponse);
        }
        // Token material never rides in the response body: the cookies above are the only
        // thing the caller needs, and putting tokens in JS-readable JSON would defeat the
        // HttpOnly cookie design the moment any XSS can POST here (which auto-refresh-on-401
        // now makes routine, not rare).
        return ApiResponse.success();
    }

    @Operation(summary = "Me", description = "Get current user info")
    @GetMapping("/me")
    public ApiResponse<UserResponse> getMe() {
        log.info("Me request received");
        return ApiResponse.success(authService.me());
    }

    private void writeSession(HttpServletResponse response, AuthResponse auth) {
        authCookies.writeAccess(response, auth.getAccessToken(),
                Math.toIntExact(Duration.ofMillis(accessTokenTtlMillis).toSeconds()));
        authCookies.writeRefresh(response, auth.getRefreshToken(), REFRESH_TOKEN_MAX_AGE);
    }

    private void writeOAuthCookie(HttpServletResponse response, String name, String value, int maxAge) {
        authCookies.writeOAuth(response, name, value, maxAge, OAUTH_COOKIE_PATH);
    }
}
