package vn.thanhtuanle.common.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.UserLockTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GlobalExceptionHandlerRetryAfterTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void loginRateLimit_keepsItsFixed900() {
        // What LoginRateLimiter throws for a locked login, answered by the shared handler.
        ResponseEntity<ApiResponse<Object>> res = handler.handleRateLimitedException(
                new RateLimitedException(ErrorCode.RATE_LIMITED, LoginRateLimiter.LOCK_SECONDS));
        assertThat(res.getStatusCode().value()).isEqualTo(429);
        assertThat(res.getHeaders().getFirst("Retry-After")).isEqualTo("900");
    }

    /** A call that gave up on a user row held past the lock timeout. */
    @RestController
    static class BusyAccount {
        @GetMapping("/busy")
        String busy() {
            throw new UserLockTimeoutException(new RuntimeException("lock timeout"));
        }
    }

    @Test
    void aBusyAccountIs503_andSaysToRetryInFiveSeconds() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new BusyAccount()).setControllerAdvice(handler).build();

        mockMvc.perform(get("/busy"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "5"))
                .andExpect(jsonPath("$.message").value(ErrorCode.ACCOUNT_BUSY.getMessage()));
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void accountBusyIsLoggedAtWarnWithoutAStack(CapturedOutput output) throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new BusyAccount()).setControllerAdvice(handler).build();

        mockMvc.perform(get("/busy"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().string(containsString("\"code\":\"ACCOUNT_BUSY\"")));

        assertThat(output).contains("ACCOUNT_BUSY (503), Retry-After 5s");
        assertThat(output.getAll().lines().filter(line -> line.contains("ACCOUNT_BUSY (503)")))
                .singleElement().asString().contains("WARN");
        assertThat(output).doesNotContain("\tat ");
    }
}
