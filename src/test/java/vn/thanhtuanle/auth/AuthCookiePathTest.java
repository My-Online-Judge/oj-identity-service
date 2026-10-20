package vn.thanhtuanle.auth;

import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import vn.thanhtuanle.config.SecurityConfig;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.oj.common.web.security.OjAccessDeniedHandler;
import vn.thanhtuanle.oj.common.web.security.OjAuthenticationEntryPoint;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The refresh cookie is scoped to /api/v1/auth, so the browser sends it only to the auth endpoints; the access cookie
 * stays at /. Every browser still holds a refresh cookie at Path=/ from before, so writing the new one also expires
 * that, and logout expires both. A stale Path=/ token presented later would count as reuse and end every session.
 * Headers are rendered the way the embedded Tomcat writes them (see AuthCookieAttributesTest).
 */
@WebMvcTest(controllers = AuthController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class, AuthCookies.class})
@ActiveProfiles("test")
class AuthCookiePathTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean AuthService authService;
    @MockitoBean JwtDecoder jwtDecoder;
    @MockitoBean UserDetailsService userDetailsService;

    @Test
    void loginScopesTheRefreshCookieAndExpiresTheLegacyOne() throws Exception {
        List<String> headers = AuthCookieAttributesTest.loginSetCookies(mockMvc, authService);

        assertThat(headers)
                .anySatisfy(h -> assertThat(h).startsWith("accessToken=AT;").contains("; Path=/;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=RT;").contains("; Path=/api/v1/auth;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=;").contains("; Max-Age=0;", "; Path=/;"));
    }

    @Test
    void logoutExpiresTheRefreshCookieOnBothPaths() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/logout")).andExpect(status().isOk()).andReturn();
        Rfc6265CookieProcessor tomcat = new Rfc6265CookieProcessor();
        List<String> headers = Arrays.stream(result.getResponse().getCookies())
                .map(cookie -> tomcat.generateHeader(cookie, null))
                .toList();

        assertThat(headers)
                .anySatisfy(h -> assertThat(h).startsWith("accessToken=;").contains("; Max-Age=0;", "; Path=/;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=;").contains("; Max-Age=0;", "; Path=/;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=;")
                        .contains("; Max-Age=0;", "; Path=/api/v1/auth;"));
    }
}
