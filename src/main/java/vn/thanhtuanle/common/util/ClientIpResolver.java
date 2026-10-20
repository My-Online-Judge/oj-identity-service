package vn.thanhtuanle.common.util;

import jakarta.servlet.http.HttpServletRequest;
import vn.thanhtuanle.oj.common.tls.PeerCertificates;

import java.security.cert.X509Certificate;

/**
 * Resolve the originating client IP of a request. {@code X-Forwarded-For} is client-controlled
 * unless a trusted proxy set it, so its first hop is honoured only when the mTLS peer
 * certificate's CN is the api-gateway; otherwise the socket's remote address is used.
 */
public final class ClientIpResolver {

    static final String TRUSTED_PROXY_CN = "api-gateway";
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank() && fromGateway(request)) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static boolean fromGateway(HttpServletRequest request) {
        Object attr = request.getAttribute(CERT_ATTRIBUTE);
        if (attr instanceof X509Certificate[] chain && chain.length > 0) {
            return PeerCertificates.commonName(chain[0]).filter(TRUSTED_PROXY_CN::equals).isPresent();
        }
        return false;
    }
}
