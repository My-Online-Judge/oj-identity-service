package vn.thanhtuanle.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * CORS is answered by the api-gateway (oj-api-gateway). If this service also emitted
 * Access-Control-* headers, a browser would see Access-Control-Allow-Origin twice and reject the
 * response, so this service must emit none — for simple requests and preflights alike.
 *
 * <p>The origin is the Vite dev server, {@code http://localhost:5173}: MockMvc requests target
 * {@code http://localhost:80}, so {@code Origin: http://localhost} would be SAME-origin and Spring
 * would not treat it as a CORS request at all — the test would pass without proving anything.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CorsOwnedByGatewayTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void simpleRequestFromThePortalGetsNoCorsHeaders() throws Exception {
        mockMvc.perform(get("/api/v1/languages").header("Origin", "http://localhost:5173"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Credentials"));
    }

    @Test
    void preflightFromThePortalGetsNoCorsHeaders() throws Exception {
        mockMvc.perform(options("/api/v1/submissions")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }
}
