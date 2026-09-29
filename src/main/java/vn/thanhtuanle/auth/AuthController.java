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
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.user.dto.UserResponse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

@RestController
@RequestMapping(Routes.AUTH)
@RequiredArgsConstructor
@Tag(name = "Auth Controller")
@Slf4j
public class AuthController {

    private static final String ACCESS_TOKEN_COOKIE = "accessToken";
    private static final String REFRESH_TOKEN_COOKIE = "refreshToken";
    private static final String OAUTH_STATE_COOKIE = "oauthState";
    private static final int ACCESS_TOKEN_MAX_AGE = 24 * 60 * 60; // 1 day
    private static final int REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60; // 7 days
    private static final int OAUTH_STATE_MAX_AGE = 5 * 60; // one login round-trip

    private final AuthService authService;

    /** Set true in prod (HTTPS) so auth cookies carry the Secure flag. */
    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    /**
     * Frontend origin the browser is sent back to once Google redirects here.
     * Because the redirect_uri registered with Google points at this API, the SPA can
     * move between ports/hosts by changing only this value — no Google Console edit.
     */
    @Value("${app.base-url:http://localhost:5173}")
    private String appBaseUrl;

    @Operation(summary = "Get Google Auth URL", description = "Get URL to redirect user to Google Login")
    @GetMapping("/outbound/google")
    public ApiResponse<Map<String, String>> getGoogleAuthUrl(HttpServletResponse response) {
        Map<String, String> auth = authService.getGoogleAuthUrl();
        // Google now redirects straight back to this API, so the SPA never sees the state.
        // Park it in a short-lived HttpOnly cookie and compare it on the callback.
        addCookie(response, OAUTH_STATE_COOKIE, auth.get("state"), OAUTH_STATE_MAX_AGE);
        return ApiResponse.success(Map.of("url", auth.get("url")));
    }

    @Operation(summary = "Google OAuth callback", description = "Google redirects the browser here; exchanges the code, sets auth cookies, then returns the browser to the app")
    @GetMapping("/outbound/google/callback")
    public void googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @CookieValue(value = OAUTH_STATE_COOKIE, required = false) String expectedState,
            HttpServletRequest httpRequest,
            HttpServletResponse response) throws IOException {
        addCookie(response, OAUTH_STATE_COOKIE, null, 0); // one-shot: always burn the state

        if (error != null || code == null || !statesMatch(state, expectedState)) {
            log.warn("Google callback rejected (error={}, hasCode={}, stateMatched={})",
                    error, code != null, statesMatch(state, expectedState));
            response.sendRedirect(appBaseUrl + "/problems?login=failed");
            return;
        }

        try {
            AuthResponse auth = authService.authenticateGoogleUser(code, ClientMeta.from(httpRequest));
            addCookie(response, ACCESS_TOKEN_COOKIE, auth.getAccessToken(), ACCESS_TOKEN_MAX_AGE);
            addCookie(response, REFRESH_TOKEN_COOKIE, auth.getRefreshToken(), REFRESH_TOKEN_MAX_AGE);
            response.sendRedirect(appBaseUrl + "/problems?login=ok");
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
        addCookie(response, ACCESS_TOKEN_COOKIE, auth.getAccessToken(), ACCESS_TOKEN_MAX_AGE);
        addCookie(response, REFRESH_TOKEN_COOKIE, auth.getRefreshToken(), REFRESH_TOKEN_MAX_AGE);
        return ApiResponse.success();
    }

    @Operation(summary = "Logout", description = "Logout user and clear cookies")
    @PostMapping("/logout")
    public ApiResponse<Void> logout(HttpServletResponse response) {
        authService.logout();
        addCookie(response, ACCESS_TOKEN_COOKIE, null, 0);
        addCookie(response, REFRESH_TOKEN_COOKIE, null, 0);
        return ApiResponse.success();
    }

    @Operation(summary = "Introspect Token", description = "Check if token is valid")
    @PostMapping("/introspect")
    public ApiResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request) {
        return ApiResponse.success(authService.introspect(request));
    }

    @Operation(summary = "Refresh access token", description = "Exchange a valid refresh token for a new access token, set as an HttpOnly cookie")
    @PostMapping("/refresh")
    public ApiResponse<Void> refresh(
            @CookieValue(value = REFRESH_TOKEN_COOKIE, required = false) String refreshCookie,
            @RequestBody(required = false) Map<String, String> body,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        String refreshToken = refreshCookie != null ? refreshCookie
                : (body != null ? body.get("refreshToken") : null);
        var authResponse = authService.refreshAccessToken(refreshToken, ClientMeta.from(httpRequest));
        addCookie(response, ACCESS_TOKEN_COOKIE, authResponse.getAccessToken(), ACCESS_TOKEN_MAX_AGE);
        // Token material never rides in the response body: the cookie above is the only
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

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }
}
