package vn.thanhtuanle.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import vn.thanhtuanle.oj.common.web.error.OjExceptionHandler;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;

/**
 * identity-service answers errors with the handlers every OJ service shares. A login or password-change refusal is a
 * RateLimitedException carrying what is left of its lock, so its Retry-After needs no handler of its own.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends OjExceptionHandler {

    /**
     * A write that a unique index on users refused (a username or email taken in another case, or a write that raced
     * another) answers 409 with the same message as the service's own check. Any other violation is a 500.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<Object>> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        return UniqueUserConstraints.toErrorCode(ex)
                .map(code -> {
                    log.warn("A unique index on users refused the write: {}", code.name());
                    return ResponseEntity.status(code.getStatusCode())
                            .body(ApiResponse.error(code.getStatusCode().value(), code.getMessage()));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(handleGlobalException(ex)));
    }
}
