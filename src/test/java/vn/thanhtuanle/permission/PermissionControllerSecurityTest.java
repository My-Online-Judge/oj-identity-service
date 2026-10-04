package vn.thanhtuanle.permission;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import vn.thanhtuanle.oj.common.web.security.OjAccessDeniedHandler;
import vn.thanhtuanle.oj.common.web.security.OjAuthenticationEntryPoint;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.config.SecurityConfig;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = PermissionController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class})
@ActiveProfiles("test")
class PermissionControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PermissionService permissionService;
    @MockBean
    private JwtDecoder jwtDecoder;
    @MockBean
    private UserDetailsService userDetailsService;

    @Test
    @WithMockUser(authorities = "permission:read")
    void allowed_withPermissionRead() throws Exception {
        mockMvc.perform(get("/api/v1/permissions")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "ADMIN")
    void forbidden_withOnlyAdminAuthority() throws Exception {
        mockMvc.perform(get("/api/v1/permissions")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "role:read")
    void forbidden_withWrongPermission() throws Exception {
        mockMvc.perform(get("/api/v1/permissions")).andExpect(status().isForbidden());
    }
}
