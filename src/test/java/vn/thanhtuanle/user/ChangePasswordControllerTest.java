package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.auth.AuthCookies;
import vn.thanhtuanle.config.SecurityConfig;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.oj.common.web.security.OjAccessDeniedHandler;
import vn.thanhtuanle.oj.common.web.security.OjAuthenticationEntryPoint;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = UserController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class, AuthCookies.class})
@ActiveProfiles("test")
class ChangePasswordControllerTest {

    private static final String BODY = "{\"currentPassword\":\"OldPass12\",\"newPassword\":\"NewPass12\"}";

    @Autowired MockMvc mockMvc;
    @MockBean UserService userService;
    @MockBean JwtDecoder jwtDecoder;
    @MockBean UserDetailsService userDetailsService;

    @Test
    void anonymousGets401() throws Exception {
        mockMvc.perform(put("/api/v1/users/me/password").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void authenticatedChangeClearsCookies() throws Exception {
        mockMvc.perform(put("/api/v1/users/me/password").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(header().stringValues("Set-Cookie",
                        hasItem(allOf(startsWith("accessToken="), containsString("Max-Age=0")))))
                .andExpect(header().stringValues("Set-Cookie",
                        hasItem(allOf(startsWith("refreshToken="), containsString("Max-Age=0")))));
        verify(userService).changeOwnPassword("OldPass12", "NewPass12");
    }
}
