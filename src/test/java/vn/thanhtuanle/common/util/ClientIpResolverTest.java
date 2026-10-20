package vn.thanhtuanle.common.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientIpResolverTest {

    static X509Certificate cert(String name) throws Exception {
        try (InputStream in = Files.newInputStream(Path.of("src/test/resources/tls/" + name))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private HttpServletRequest request(String xff, String remote, X509Certificate peer) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("X-Forwarded-For")).thenReturn(xff);
        when(req.getRemoteAddr()).thenReturn(remote);
        if (peer != null) {
            when(req.getAttribute("jakarta.servlet.request.X509Certificate"))
                    .thenReturn(new X509Certificate[] {peer});
        }
        return req;
    }

    @Test
    void forwardedForTrustedFromGatewayCertificate() throws Exception {
        assertThat(ClientIpResolver.resolve(
                request("203.0.113.7, 10.0.0.5", "10.0.0.2", cert("api-gateway.crt"))))
                .isEqualTo("203.0.113.7");
    }

    @Test
    void forwardedForIgnoredWithoutCertificate() {
        assertThat(ClientIpResolver.resolve(request("203.0.113.7", "10.0.0.9", null)))
                .isEqualTo("10.0.0.9");
    }

    @Test
    void forwardedForIgnoredFromOtherCertificate() throws Exception {
        assertThat(ClientIpResolver.resolve(request("203.0.113.7", "10.0.0.9", cert("tls-probe.crt"))))
                .isEqualTo("10.0.0.9");
    }

    @Test
    void gatewayCertificateWithoutHeaderFallsBackToRemote() throws Exception {
        assertThat(ClientIpResolver.resolve(request(null, "10.0.0.2", cert("api-gateway.crt"))))
                .isEqualTo("10.0.0.2");
    }
}
