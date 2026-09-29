package vn.thanhtuanle.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import vn.thanhtuanle.common.payload.ApiResponse;
import org.springframework.security.access.AccessDeniedException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<Object> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error("IllegalArgumentException: ", ex);
        return ApiResponse.error(HttpStatus.BAD_REQUEST.value(), ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<Object> handleValidationExceptions(MethodArgumentNotValidException ex) {
        log.error("Validation error: ", ex);
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        String message = "Validation failed";
        if (!errors.isEmpty()) {
            message = errors.values().iterator().next();
        }

        return ApiResponse.error(HttpStatus.BAD_REQUEST.value(), message, errors);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<Object> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex) {
        log.error("Malformed JSON request: ", ex);
        return ApiResponse.error(HttpStatus.BAD_REQUEST.value(), "Malformed JSON request: " + ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse<Object> handleGlobalException(Exception ex) {
        log.error("Internal Server Error: ", ex);
        return ApiResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error: " + ex.getMessage());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiResponse<Object> handleResourceNotFoundException(
            ResourceNotFoundException ex) {
        log.error("Resource Not Found: ", ex);
        return ApiResponse.error(HttpStatus.NOT_FOUND.value(), ex.getMessage());
    }

    @ExceptionHandler(ResourceAlreadyExistException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<Object> handleResourceAlreadyExistException(
            ResourceAlreadyExistException ex) {
        log.error("Resource Already Exist: ", ex);
        return ApiResponse.error(HttpStatus.BAD_REQUEST.value(), ex.getMessage());
    }

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiResponse<Object>> handleAppException(AppException ex) {
        log.error("AppException: ", ex);
        ErrorCode errorCode = ex.getErrorCode();
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(errorCode.getStatusCode());
        if (errorCode == ErrorCode.RATE_LIMITED) {
            // 429s tell the client when the 15-minute lock will have expired.
            builder.header(org.springframework.http.HttpHeaders.RETRY_AFTER,
                    String.valueOf(vn.thanhtuanle.security.LoginRateLimiter.LOCK_SECONDS));
        }
        return builder.body(ApiResponse.error(errorCode.getStatusCode().value(), errorCode.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApiResponse<Object> handleAccessDeniedException(
            AccessDeniedException ex) {
        log.error("Access Denied: ", ex);
        return ApiResponse.error(HttpStatus.FORBIDDEN.value(), "Access Denied: " + ex.getMessage());
    }
}
