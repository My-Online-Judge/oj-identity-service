package vn.thanhtuanle.role;

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

@WebMvcTest(controllers = RoleController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class})
@ActiveProfiles("test")
class RoleControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RoleService roleService;
    @MockBean
    private JwtDecoder jwtDecoder;
    @MockBean
    private UserDetailsService userDetailsService;

    @Test
    @WithMockUser(authorities = "role:read")
    void allowed_withRoleRead() throws Exception {
        mockMvc.perform(get("/api/v1/roles")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "ADMIN")
    void forbidden_withOnlyAdminAuthority() throws Exception {
        mockMvc.perform(get("/api/v1/roles")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "permission:read")
    void forbidden_withWrongPermission() throws Exception {
        mockMvc.perform(get("/api/v1/roles")).andExpect(status().isForbidden());
    }

    @Test
    void unauthorized_withNoToken() throws Exception {
        // No @WithMockUser: this exercises the real filter chain (OjJwtAuthenticationFilter +
        // OjAuthenticationEntryPoint) end to end, not just the entry point bean in
        // isolation. 401 = "not authenticated, go refresh" -- distinct from the 403 RBAC
        // denials above, which must stay 403.
        mockMvc.perform(get("/api/v1/roles")).andExpect(status().isUnauthorized());
    }
}
