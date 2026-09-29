package vn.thanhtuanle.common.util;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolve the originating client IP of a request: the first hop of {@code X-Forwarded-For}
 * (set by a fronting proxy), falling back to the socket's remote address.
 */
public final class ClientIpResolver {

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
