package vn.thanhtuanle.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthEndpointAccessTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void anonymousMeIs401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void anonymousOutboundGoogleIsPublic() throws Exception {
        mockMvc.perform(get("/api/v1/auth/outbound/google")).andExpect(status().isOk());
    }

    @Test
    void h2ConsoleIsNotWhitelisted() throws Exception {
        mockMvc.perform(get("/h2-console/")).andExpect(status().isUnauthorized());
    }
}
