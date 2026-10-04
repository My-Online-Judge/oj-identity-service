package vn.thanhtuanle.common.exception;

import org.springframework.web.bind.annotation.RestControllerAdvice;
import vn.thanhtuanle.oj.common.web.error.OjExceptionHandler;

/**
 * identity-service answers errors with the handlers every OJ service shares. The login lock is a
 * RateLimitedException carrying its 15 minutes, so its Retry-After needs no handler of its own.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends OjExceptionHandler {
}
