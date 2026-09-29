package vn.thanhtuanle.common.util;

import jakarta.servlet.http.HttpServletRequest;
import vn.thanhtuanle.oj.common.client.ClientFingerprint;


/**
 * Per-request client telemetry captured at login / token issue. {@code deviceHash} follows
 * {@link ClientFingerprint} — the same rule the api-gateway uses to enforce device bans. All fields
 * are sized to their DB columns.
 */
public record ClientMeta(String ip, String deviceHash, String userAgent) {

    public static ClientMeta from(HttpServletRequest request) {
        String userAgent = ClientFingerprint.truncate(request.getHeader("User-Agent"), ClientFingerprint.USER_AGENT_MAX);
        String deviceHash = ClientFingerprint.deviceHash(request.getHeader("X-Device-Id"), request.getHeader("User-Agent"));
        return new ClientMeta(ClientIpResolver.resolve(request), deviceHash, userAgent);
    }
}
