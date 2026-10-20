package vn.thanhtuanle.auth;

import jakarta.servlet.http.Cookie;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.UserRepository;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Logout must work in the common case of an expired access token (15 minutes): the request is then anonymous, and
 * the user is found through the refresh cookie, which the browser sends to /api/v1/auth. Whatever happens, the
 * response expires the session cookies, or the portal reloads and the refresh cookie signs the user back in.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LogoutIntegrationTest {

    private static final String PASSWORD = "Secret123";

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired TokenRepository tokenRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @MockitoBean SessionRevoker sessionRevoker;
    @MockitoBean LoginRateLimiter loginRateLimiter;

    private User user;

    @BeforeEach
    void seedUser() {
        String username = "out_" + UUID.randomUUID().toString().substring(0, 8);
        user = userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode(PASSWORD))
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
    }

    @Test
    void anExpiredAccessCookieAndTheRefreshCookieEndEverySession() throws Exception {
        String refreshToken = login();

        // The access cookie no longer verifies (expired), so the request reaches logout anonymous.
        MockHttpServletResponse response = mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(new Cookie("accessToken", "expired.access.token"),
                                new Cookie("refreshToken", refreshToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        assertSessionEnded(response);
    }

    @Test
    void theRefreshCookieAloneEndsEverySession() throws Exception {
        String refreshToken = login();

        MockHttpServletResponse response = mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(new Cookie("refreshToken", refreshToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        assertSessionEnded(response);
    }

    @Test
    void noCookiesAtAllStillAnswers200AndExpiresTheCookies() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        assertCookiesExpired(response);
        verifyNoInteractions(sessionRevoker);
    }

    private void assertSessionEnded(MockHttpServletResponse response) {
        assertThat(tokenRepository.findAll()).noneMatch(t -> t.getUser().getId().equals(user.getId()));
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(user.getId()));
        assertCookiesExpired(response);
    }

    private static void assertCookiesExpired(MockHttpServletResponse response) {
        Rfc6265CookieProcessor tomcat = new Rfc6265CookieProcessor();
        List<String> headers = Arrays.stream(response.getCookies())
                .map(cookie -> tomcat.generateHeader(cookie, null))
                .toList();
        assertThat(headers)
                .anySatisfy(h -> assertThat(h).startsWith("accessToken=;").contains("; Max-Age=0;", "; Path=/;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=;").contains("; Max-Age=0;", "; Path=/;"))
                .anySatisfy(h -> assertThat(h).startsWith("refreshToken=;")
                        .contains("; Max-Age=0;", "; Path=/api/v1/auth;"));
    }

    /** Logs the seeded user in; returns the refresh token the login set. */
    private String login() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user.getUsername() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse();
        return Arrays.stream(response.getCookies())
                .filter(c -> c.getName().equals("refreshToken") && c.getMaxAge() > 0)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no refreshToken cookie was set"))
                .getValue();
    }
}
