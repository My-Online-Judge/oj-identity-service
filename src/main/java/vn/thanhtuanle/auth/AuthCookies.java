package vn.thanhtuanle.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Auth-cookie writing shared by the auth and user controllers. */
@Component
public class AuthCookies {

    static final String ACCESS_TOKEN_COOKIE = "accessToken";
    static final String REFRESH_TOKEN_COOKIE = "refreshToken";

    /** Set true in prod (HTTPS) so auth cookies carry the Secure flag. */
    @Value("${app.cookie.secure:false}")
    private boolean secure;

    static void write(HttpServletResponse response, String name, String value, int maxAge, boolean secure) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    /** Expire both session cookies in the browser. */
    public void clearSession(HttpServletResponse response) {
        write(response, ACCESS_TOKEN_COOKIE, null, 0, secure);
        write(response, REFRESH_TOKEN_COOKIE, null, 0, secure);
    }
}
