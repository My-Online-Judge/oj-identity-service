package vn.thanhtuanle.common.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import vn.thanhtuanle.common.payload.ApiResponse;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerRetryAfterTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void loginRateLimit_keepsItsFixed900() {
        ResponseEntity<ApiResponse<Object>> res =
                handler.handleAppException(new AppException(ErrorCode.RATE_LIMITED));
        assertThat(res.getHeaders().getFirst("Retry-After")).isEqualTo("900");
    }
}
