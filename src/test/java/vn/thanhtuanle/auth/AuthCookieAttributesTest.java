package vn.thanhtuanle.auth;

import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.config.SecurityConfig;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.oj.common.web.security.OjAccessDeniedHandler;
import vn.thanhtuanle.oj.common.web.security.OjAuthenticationEntryPoint;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The auth cookies are HttpOnly and SameSite=Lax: with the portal and the API on one origin behind the edge, a cross-site
 * page cannot make the browser send them on a POST. Behind HTTPS (app.cookie.secure, APP_COOKIE_SECURE in compose) they
 * are Secure too. The Set-Cookie text checked is what the embedded Tomcat writes for the response's cookies: MockMvc's
 * own Set-Cookie rendering leaves out cookie attributes such as SameSite.
 */
@WebMvcTest(controllers = AuthController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class, AuthCookies.class})
@ActiveProfiles("test")
class AuthCookieAttributesTest {

    private static final String LOGIN = "{\"username\":\"admin\",\"password\":\"Secret123\"}";

    @Autowired MockMvc mockMvc;
    @MockBean AuthService authService;
    @MockBean JwtDecoder jwtDecoder;
    @MockBean UserDetailsService userDetailsService;

    /** Logs in through the controller; returns the Set-Cookie headers Tomcat sends for the two session cookies. */
    static List<String> loginSetCookies(MockMvc mockMvc, AuthService authService) throws Exception {
        when(authService.authenticateWithPassword(eq("admin"), eq("Secret123"), any(ClientMeta.class)))
                .thenReturn(AuthResponse.builder().accessToken("AT").refreshToken("RT").build());
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(LOGIN))
                .andExpect(status().isOk())
                .andReturn();
        Rfc6265CookieProcessor tomcat = new Rfc6265CookieProcessor();
        List<String> headers = Arrays.stream(result.getResponse().getCookies())
                .map(cookie -> tomcat.generateHeader(cookie, null))
                .toList();
        assertThat(headers).anySatisfy(h -> assertThat(h).startsWith("accessToken=AT;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=RT;"));
        return headers;
    }

    /**
     * The outbound call sets the three OAuth cookies and the callback expires them; returns every Set-Cookie header Tomcat
     * sends for them.
     */
    static List<String> oauthSetCookies(MockMvc mockMvc, AuthService authService) throws Exception {
        when(authService.getGoogleAuthUrl()).thenReturn(new GoogleAuthorization(
                "https://accounts.google.com/o/oauth2/auth?x=1", "s-1", "v-1", "n-1"));
        Rfc6265CookieProcessor tomcat = new Rfc6265CookieProcessor();
        List<String> headers = new java.util.ArrayList<>();
        for (MvcResult result : List.of(
                mockMvc.perform(get("/api/v1/auth/outbound/google")).andExpect(status().isOk()).andReturn(),
                mockMvc.perform(get("/api/v1/auth/outbound/google/callback")).andReturn())) {
            Arrays.stream(result.getResponse().getCookies())
                    .filter(cookie -> cookie.getName().startsWith("oauth"))
                    .map(cookie -> tomcat.generateHeader(cookie, null))
                    .forEach(headers::add);
        }
        assertThat(headers).anySatisfy(h -> assertThat(h).startsWith("oauthState=s-1;"))
                .anySatisfy(h -> assertThat(h).startsWith("oauthVerifier=v-1;"))
                .anySatisfy(h -> assertThat(h).startsWith("oauthNonce=n-1;"))
                .anySatisfy(h -> assertThat(h).startsWith("oauthNonce=;").contains("Max-Age=0"));
        return headers;
    }

    @Test
    void oauthCookiesAreHttpOnlySameSiteLax() throws Exception {
        assertThat(oauthSetCookies(mockMvc, authService)).allSatisfy(h -> assertThat(h)
                .contains("; HttpOnly", "; SameSite=Lax")
                .doesNotContain("Secure"));
    }

    @Test
    void loginSetsHttpOnlySameSiteLaxCookies() throws Exception {
        assertThat(loginSetCookies(mockMvc, authService)).allSatisfy(h -> assertThat(h)
                .contains("; HttpOnly", "; SameSite=Lax")
                .doesNotContain("Secure"));
    }

    @Nested
    @TestPropertySource(properties = "app.cookie.secure=true")
    class BehindHttps {

        // This class runs in its own context (the property above): its beans, not the enclosing instance's.
        @Autowired MockMvc httpsMockMvc;
        @Autowired AuthService httpsAuthService;

        @Test
        void loginCookiesAreSecureToo() throws Exception {
            assertThat(loginSetCookies(httpsMockMvc, httpsAuthService)).allSatisfy(h -> assertThat(h)
                    .contains("; HttpOnly", "; SameSite=Lax", "; Secure"));
        }

        @Test
        void oauthCookiesAreSecureToo() throws Exception {
            assertThat(oauthSetCookies(httpsMockMvc, httpsAuthService)).allSatisfy(h -> assertThat(h)
                    .contains("; HttpOnly", "; SameSite=Lax", "; Secure"));
        }
    }
}
