package vn.thanhtuanle.common.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final String REQUEST_ID_MDC_KEY = "requestId";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestId = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        MDC.put(REQUEST_ID_MDC_KEY, requestId);

        long startTime = System.currentTimeMillis();
        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        log.info("Incoming request: {} {}", method, requestUri);

        try {
            filterChain.doFilter(request, response);
        } finally {
            long durationMs = System.currentTimeMillis() - startTime;
            double durationSec = durationMs / 1000.0;
            int status = response.getStatus();
            log.info("Request finished: {} {} - Status: {} - Time: {}s", method, requestUri, status,
                    String.format("%.4f", durationSec));
            MDC.remove(REQUEST_ID_MDC_KEY);
        }
    }
}
