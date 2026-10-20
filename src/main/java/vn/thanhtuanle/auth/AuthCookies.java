package vn.thanhtuanle.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Auth-cookie writing shared by the auth and user controllers: every cookie the service sets goes through
 * {@link #write}. SameSite=Lax: the portal and the API share one origin behind the edge, so a cross-site page cannot
 * make the browser send the session on a POST.
 *
 * <p>The access cookie is at {@code /}, because every API call needs it. The refresh cookie is at
 * {@link #REFRESH_COOKIE_PATH}, so the browser sends it only to the auth endpoints (refresh, logout).
 */
@Component
public class AuthCookies {

    static final String ACCESS_TOKEN_COOKIE = "accessToken";
    static final String REFRESH_TOKEN_COOKIE = "refreshToken";
    /** Where the browser reaches the auth endpoints through the edge. */
    static final String REFRESH_COOKIE_PATH = "/api/v1/auth";
    private static final String ROOT_PATH = "/";

    /** Set true in prod (HTTPS) so auth cookies carry the Secure flag. */
    @Value("${app.cookie.secure:false}")
    private boolean secure;

    static void write(HttpServletResponse response, String name, String value, int maxAge, boolean secure,
                      String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(path);
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }

    public void writeAccess(HttpServletResponse response, String value, int maxAge) {
        write(response, ACCESS_TOKEN_COOKIE, value, maxAge, secure, ROOT_PATH);
    }

    /**
     * Sets the refresh cookie and expires the one earlier versions set at {@code Path=/}. A browser that kept both
     * would later present the stale {@code /} token, which counts as reuse and signs the user out everywhere.
     */
    public void writeRefresh(HttpServletResponse response, String value, int maxAge) {
        write(response, REFRESH_TOKEN_COOKIE, value, maxAge, secure, REFRESH_COOKIE_PATH);
        write(response, REFRESH_TOKEN_COOKIE, null, 0, secure, ROOT_PATH);
    }

    /** Expire both session cookies in the browser, the refresh cookie at its current and its legacy path. */
    public void clearSession(HttpServletResponse response) {
        write(response, ACCESS_TOKEN_COOKIE, null, 0, secure, ROOT_PATH);
        write(response, REFRESH_TOKEN_COOKIE, null, 0, secure, REFRESH_COOKIE_PATH);
        write(response, REFRESH_TOKEN_COOKIE, null, 0, secure, ROOT_PATH);
    }
}
