package vn.thanhtuanle.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.util.ClientMeta;

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

    @Mock
    AuthService authService;

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
        when(authService.authenticateGoogleUser(eq("the-code"), any(ClientMeta.class)))
                .thenReturn(AuthResponse.builder().accessToken("AT").refreshToken("RT").build());

        controller.googleCallback("the-code", "state-123", null, "state-123", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=ok");
        assertThat(response.getCookie("accessToken").getValue()).isEqualTo("AT");
        assertThat(response.getCookie("refreshToken").getValue()).isEqualTo("RT");
        // The whole point of moving the callback server-side: JS must never read these.
        assertThat(response.getCookie("accessToken").isHttpOnly()).isTrue();
        assertThat(response.getCookie("refreshToken").isHttpOnly()).isTrue();
    }

    @Test
    void callback_withMismatchedState_isRejected_andNeverExchangesTheCode() throws IOException {
        controller.googleCallback("the-code", "attacker-state", null, "expected-state", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
        verify(authService, never()).authenticateGoogleUser(any(), any());
    }

    @Test
    void callback_withoutStateCookie_isRejected() throws IOException {
        controller.googleCallback("the-code", "state-123", null, null, request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
        verify(authService, never()).authenticateGoogleUser(any(), any());
    }

    @Test
    void callback_whenGoogleReturnsError_isRejected() throws IOException {
        controller.googleCallback(null, "state-123", "access_denied", "state-123", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        verify(authService, never()).authenticateGoogleUser(any(), any());
    }

    @Test
    void callback_whenCodeExchangeFails_returnsToAppWithFailure_andSetsNoAuthCookies() throws IOException {
        when(authService.authenticateGoogleUser(eq("bad-code"), any(ClientMeta.class))).thenThrow(new RuntimeException("google said no"));

        controller.googleCallback("bad-code", "state-123", null, "state-123", request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo(APP + "/problems?login=failed");
        assertThat(response.getCookie("accessToken")).isNull();
    }

    @Test
    void authUrl_parksStateInAnHttpOnlyCookie_andDoesNotLeakItToTheSpa() {
        when(authService.getGoogleAuthUrl())
                .thenReturn(java.util.Map.of("url", "https://accounts.google.com/o/oauth2/auth?x=1", "state", "s-42"));

        var body = controller.getGoogleAuthUrl(response);

        assertThat(response.getCookie("oauthState").getValue()).isEqualTo("s-42");
        assertThat(response.getCookie("oauthState").isHttpOnly()).isTrue();
        assertThat(body.getData()).containsOnlyKeys("url");
    }
}
