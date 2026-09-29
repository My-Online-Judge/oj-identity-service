package vn.thanhtuanle.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CustomAuthenticationEntryPointTest {

    private final CustomAuthenticationEntryPoint entryPoint = new CustomAuthenticationEntryPoint();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void unauthenticatedRequest_gets401_soTheClientKnowsToRefresh() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(new MockHttpServletRequest(), response,
                new InsufficientAuthenticationException("Full authentication is required to access this resource"));

        // 401 = "you are not authenticated" (refreshable). 403 stays reserved for
        // "authenticated but not permitted", which no refresh can fix.
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void responseBodyCarriesTheSame401Status() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(new MockHttpServletRequest(), response,
                new InsufficientAuthenticationException("nope"));

        Map<?, ?> body = objectMapper.readValue(response.getContentAsString(), Map.class);
        assertThat(body.get("status")).isEqualTo(401);
        assertThat(String.valueOf(body.get("message"))).contains("nope");
    }
}
