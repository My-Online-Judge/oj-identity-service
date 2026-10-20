package vn.thanhtuanle.auth;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.UserRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Refresh-token rotation end to end (H2): every refresh replaces the refresh token; the replaced one is good for a
 * 10-second grace (concurrent tabs refreshing at once get 200 and nothing new), and after that presenting it again is
 * treated as theft: every session of the user ends, committed even though the request answers 401.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RefreshRotationIntegrationTest {

    private static final String PASSWORD = "Secret123";
    private static final String REUSED_MESSAGE = "Refresh token was already used; every session has been signed out";

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired TokenRepository tokenRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired MutableClock clock;
    @Autowired vn.thanhtuanle.common.util.JwtUtil jwtUtil;

    @MockitoBean SessionRevoker sessionRevoker;
    @MockitoBean LoginRateLimiter loginRateLimiter;

    private User user;

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock();
        }
    }

    /** A clock the test moves forward by hand. */
    static final class MutableClock extends Clock {
        private volatile Instant now = Instant.now();

        void reset() {
            now = Instant.now();
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.systemDefault();
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @BeforeEach
    void seedUser() {
        clock.reset();
        String username = "rot_" + UUID.randomUUID().toString().substring(0, 8);
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
    void refreshRotatesTheToken() throws Exception {
        String original = login();

        MockHttpServletResponse response = refresh(original);

        assertThat(response.getStatus()).isEqualTo(200);
        Cookie rotated = liveRefreshCookie(response);
        assertThat(rotated.getValue()).isNotEqualTo(original);
        assertThat(rotated.getPath()).isEqualTo("/api/v1/auth");
        assertThat(tokenRepository.findByToken(TokenHasher.sha256Hex(original)))
                .hasValueSatisfying(row -> assertThat(row.getRotatedAt()).isNotNull());
    }

    @Test
    void theSessionEndsOneRefreshTtlAfterLogin() throws Exception {
        String original = login();

        String rotated = liveRefreshCookie(refresh(original)).getValue();

        // The successor keeps the session's end instead of sliding it a refresh TTL further.
        assertThat(jwtUtil.extractExpiration(rotated)).isEqualTo(jwtUtil.extractExpiration(original));
    }

    @Test
    void reusedTokenEndsEverySession() throws Exception {
        String original = login();
        String rotated = liveRefreshCookie(refresh(original)).getValue();

        clock.advance(Duration.ofSeconds(11));
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refreshToken", original)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(REUSED_MESSAGE));

        // The deletes commit even though the request answered 401.
        assertThat(rowsOfUser()).isEmpty();
        assertThat(refresh(rotated).getStatus()).isEqualTo(401);
        verify(sessionRevoker).revokeAccessTokensAfterCommit(List.of(user.getId()));
    }

    @Test
    void concurrentRefreshWithinGraceIssuesNothing() throws Exception {
        String original = login();
        String rotated = liveRefreshCookie(refresh(original)).getValue();
        List<String> rowsBefore = rowsOfUser();

        clock.advance(Duration.ofSeconds(2));
        MockHttpServletResponse loser = refresh(original);

        assertThat(loser.getStatus()).isEqualTo(200);
        assertThat(loser.getCookies()).isEmpty();
        assertThat(loser.getHeaders("Set-Cookie")).isEmpty();
        assertThat(rowsOfUser()).isEqualTo(rowsBefore);
        verifyNoInteractions(sessionRevoker);

        MockHttpServletResponse next = refresh(rotated);
        assertThat(next.getStatus()).isEqualTo(200);
        assertThat(liveRefreshCookie(next).getValue()).isNotEqualTo(rotated);
    }

    /** Logs the seeded user in; returns the refresh token the login set. */
    private String login() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user.getUsername() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse();
        return liveRefreshCookie(response).getValue();
    }

    private MockHttpServletResponse refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refreshToken", refreshToken)))
                .andReturn().getResponse();
    }

    /** The refreshToken cookie that carries a token (not the one expiring the legacy Path=/ cookie). */
    private static Cookie liveRefreshCookie(MockHttpServletResponse response) {
        return Arrays.stream(response.getCookies())
                .filter(c -> c.getName().equals("refreshToken") && c.getMaxAge() > 0)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no refreshToken cookie was set"));
    }

    /** The user's token rows as "type hash rotatedAt", in a stable order. */
    private List<String> rowsOfUser() {
        return tokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(user.getId()))
                .map(RefreshRotationIntegrationTest::describe)
                .sorted()
                .toList();
    }

    private static String describe(Token t) {
        return t.getTokenType() + " " + t.getToken() + " " + t.getRotatedAt();
    }
}
