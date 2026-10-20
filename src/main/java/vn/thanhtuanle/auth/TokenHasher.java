package vn.thanhtuanle.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * What {@code t_tokens.token} holds: the SHA-256 of a token, never the token, so a database leak hands out no live
 * session. The cookie keeps the token; every lookup hashes the presented one. Flyway V5 computes the same value in SQL
 * ({@code encode(sha256(convert_to(token, 'UTF8')), 'hex')}), so rows written before it still match.
 */
public final class TokenHasher {

    private TokenHasher() {
    }

    /** 64 lowercase hex characters of SHA-256 over the UTF-8 bytes of {@code raw}. */
    public static String sha256Hex(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("token must not be null");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // Every Java platform must provide SHA-256 (MessageDigest javadoc).
            throw new IllegalStateException(e);
        }
    }
}
