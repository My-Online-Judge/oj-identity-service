package vn.thanhtuanle.common.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientMetaTest {

    private HttpServletRequest request(String xff, String remoteAddr, String deviceId, String userAgent) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("X-Forwarded-For")).thenReturn(xff);
        when(req.getHeader("X-Device-Id")).thenReturn(deviceId);
        when(req.getHeader("User-Agent")).thenReturn(userAgent);
        when(req.getRemoteAddr()).thenReturn(remoteAddr);
        return req;
    }

    @Test
    void resolve_prefersFirstHopOfXForwardedFor() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 10.0.0.1");
        assertThat(ClientIpResolver.resolve(req)).isEqualTo("1.2.3.4");
    }

    @Test
    void resolve_fallsBackToRemoteAddr() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("X-Forwarded-For")).thenReturn(null);
        when(req.getRemoteAddr()).thenReturn("9.9.9.9");
        assertThat(ClientIpResolver.resolve(req)).isEqualTo("9.9.9.9");
    }

    @Test
    void from_usesXDeviceIdWhenPresent() {
        ClientMeta meta = ClientMeta.from(request("1.2.3.4", "9.9.9.9", "dev-123", "probe/1.0"));
        assertThat(meta.ip()).isEqualTo("1.2.3.4");
        assertThat(meta.deviceHash()).isEqualTo("dev-123");
        assertThat(meta.userAgent()).isEqualTo("probe/1.0");
    }

    @Test
    void from_fallsBackToUserAgentHashWhenNoDeviceId() {
        ClientMeta meta = ClientMeta.from(request(null, "9.9.9.9", "  ", "UA"));
        assertThat(meta.deviceHash())
                .isNotNull()
                .isNotEqualTo("UA")
                .matches("[0-9a-f]{64}");
    }

    @Test
    void from_truncatesOverLongUserAgent() {
        String longUa = "x".repeat(600);
        ClientMeta meta = ClientMeta.from(request(null, "9.9.9.9", "dev-1", longUa));
        assertThat(meta.userAgent()).hasSize(512);
    }
}
