package vn.thanhtuanle.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.oj.common.web.error.AppException;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerGoogleCallbackTest {

    private static final String APP = "http://localhost:5173";
    private static final String OAUTH_PATH = "/api/v1/auth/outbound/google";
    private static final String[] OAUTH_COOKIES = {"oauthState", "oauthVerifier", "oauthNonce"};

    @Mock
    AuthService authService;

    @Spy
    AuthCookies authCookies = new AuthCookies();

    @InjectMocks
    AuthController controller;

    MockHttpServletResponse response;
    HttpServletRequest request;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(controller, "appBaseUrl", APP);
        ReflectionTestUtils.setField(controller, "cookieSecure", false);
        response = new MockHttpServletResponse();
        request = mock(HttpServletRequest.class);
    }

    @Test
    void callback_withMatchingState_setsHttpOnlyAuthCookies_andReturnsBrowserToApp() throws IOException {
        when(authService.authenticateGoogleUser(eq("the-code"), eq("verifier-1"), eq("nonce-1"), any(ClientMeta.class)))
                .thenReturn(AuthResponse.builder().accessToken("AT").refreshToken("RT").build());

        controller.googleCallback("the-code", "state-123", null, "state-123", "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=ok");
        assertThat(response.getCookie("accessToken").getValue()).isEqualTo("AT");
        assertThat(response.getCookie("refreshToken").getValue()).isEqualTo("RT");
        assertThat(response.getCookie("refreshToken").getPath()).isEqualTo("/api/v1/auth");
        // The whole point of moving the callback server-side: JS must never read these.
        assertThat(response.getCookie("accessToken").isHttpOnly()).isTrue();
        assertThat(response.getCookie("refreshToken").isHttpOnly()).isTrue();
    }

    @Test
    void callback_withMismatchedState_isRejected_andNeverExchangesTheCode() throws IOException {
        controller.googleCallback("the-code", "attacker-state", null, "expected-state", "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
        verify(authService, never()).authenticateGoogleUser(any(), any(), any(), any());
    }

    @Test
    void callback_withoutStateCookie_isRejected() throws IOException {
        controller.googleCallback("the-code", "state-123", null, null, "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
        verify(authService, never()).authenticateGoogleUser(any(), any(), any(), any());
    }

    @Test
    void callback_whenGoogleReturnsError_isRejected() throws IOException {
        controller.googleCallback(null, "state-123", "access_denied", "state-123", "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        verify(authService, never()).authenticateGoogleUser(any(), any(), any(), any());
    }

    @Test
    void callback_whenCodeExchangeFails_returnsToAppWithFailure_andSetsNoAuthCookies() throws IOException {
        when(authService.authenticateGoogleUser(eq("bad-code"), any(), any(), any(ClientMeta.class))).thenThrow(new RuntimeException("google said no"));

        controller.googleCallback("bad-code", "state-123", null, "state-123", "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
    }

    @Test
    void outbound_setsThreeShortLivedCookies() {
        when(authService.getGoogleAuthUrl()).thenReturn(new GoogleAuthorization(
                "https://accounts.google.com/o/oauth2/auth?x=1", "s-42", "v-42", "n-42"));

        var body = controller.getGoogleAuthUrl(response);

        assertThat(response.getCookie("oauthState").getValue()).isEqualTo("s-42");
        assertThat(response.getCookie("oauthVerifier").getValue()).isEqualTo("v-42");
        assertThat(response.getCookie("oauthNonce").getValue()).isEqualTo("n-42");
        for (String name : OAUTH_COOKIES) {
            Cookie cookie = response.getCookie(name);
            assertThat(cookie.isHttpOnly()).as(name).isTrue();
            assertThat(cookie.getMaxAge()).as(name).isEqualTo(300);
            // Only the outbound call and its callback ever receive them.
            assertThat(cookie.getPath()).as(name).isEqualTo(OAUTH_PATH);
        }
        // The SPA gets the URL only: the state, the verifier and the nonce never reach JS.
        assertThat(body.getData()).containsOnlyKeys("url");
        assertThat(body.getData().get("url")).isEqualTo("https://accounts.google.com/o/oauth2/auth?x=1");
    }

    @Test
    void callback_passesVerifierAndNonce_andBurnsTheCookies() throws IOException {
        when(authService.authenticateGoogleUser(eq("the-code"), eq("verifier-1"), eq("nonce-1"), any(ClientMeta.class)))
                .thenReturn(AuthResponse.builder().accessToken("AT").refreshToken("RT").build());

        controller.googleCallback("the-code", "state-123", null, "state-123", "verifier-1", "nonce-1", request, response);

        verify(authService).authenticateGoogleUser(eq("the-code"), eq("verifier-1"), eq("nonce-1"), any(ClientMeta.class));
        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=ok");
        assertBurnt();
    }

    @Test
    void callback_appException_redirectsWithReason() throws IOException {
        when(authService.authenticateGoogleUser(eq("the-code"), eq("verifier-1"), eq("nonce-1"), any(ClientMeta.class)))
                .thenThrow(new AppException(ErrorCode.GOOGLE_EMAIL_UNVERIFIED));

        controller.googleCallback("the-code", "state-123", null, "state-123", "verifier-1", "nonce-1", request, response);

        assertThat(response.getRedirectedUrl())
                .isEqualTo(APP + "/problems?login=failed&reason=GOOGLE_EMAIL_UNVERIFIED");
        assertThat(response.getCookie("accessToken")).isNull();
        assertThat(response.getCookie("refreshToken")).isNull();
        assertBurnt();
    }

    @Test
    void callback_withoutVerifierOrNonceCookie_isRejected_andNeverExchangesTheCode() throws IOException {
        controller.googleCallback("the-code", "state-123", null, "state-123", null, "nonce-1", request, response);
        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertBurnt();

        response = new MockHttpServletResponse();
        controller.googleCallback("the-code", "state-123", null, "state-123", "verifier-1", null, request, response);
        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertBurnt();

        verify(authService, never()).authenticateGoogleUser(any(), any(), any(), any());
    }

    /** Each OAuth cookie is expired at the path it was set on, so the browser really drops it. */
    private void assertBurnt() {
        for (String name : OAUTH_COOKIES) {
            Cookie cookie = response.getCookie(name);
            assertThat(cookie).as(name).isNotNull();
            assertThat(cookie.getMaxAge()).as(name).isZero();
            assertThat(cookie.getPath()).as(name).isEqualTo(OAUTH_PATH);
        }
    }
}
