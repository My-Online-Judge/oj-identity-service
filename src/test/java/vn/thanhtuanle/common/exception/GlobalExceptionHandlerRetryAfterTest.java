package vn.thanhtuanle.common.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;
import vn.thanhtuanle.oj.common.web.error.RateLimitedException;
import vn.thanhtuanle.security.LoginRateLimiter;

import static org.assertj.core.api.Assertions.assertThat;

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
}
