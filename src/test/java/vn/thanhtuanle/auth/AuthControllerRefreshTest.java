package vn.thanhtuanle.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.common.util.ClientMeta;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerRefreshTest {

    @Mock
    AuthService authService;

    @InjectMocks
    AuthController controller;

    MockHttpServletResponse response;
    HttpServletRequest request;

    @BeforeEach
    void setUp() {
        response = new MockHttpServletResponse();
        request = mock(HttpServletRequest.class);
    }

    @Test
    void refresh_setsAccessTokenCookie_butLeaksNoTokenMaterialInTheBody() {
        when(authService.refreshAccessToken(any(), any(ClientMeta.class)))
                .thenReturn(AuthResponse.builder()
                        .accessToken("new-access-token")
                        .refreshToken("the-refresh-token")
                        .build());

        ApiResponse<Void> body = controller.refresh("the-refresh-token", null, request, response);

        // The endpoint sets the cookie itself -- that's the only thing the caller needs.
        assertThat(response.getCookie("accessToken").getValue()).isEqualTo("new-access-token");

        // The whole HttpOnly-cookie design rests on JS never holding a token. An XSS
        // that can POST /auth/refresh must not be able to read the refresh token (or
        // the access token) straight out of the JSON body.
        assertThat(body.getData()).isNull();
    }
}
