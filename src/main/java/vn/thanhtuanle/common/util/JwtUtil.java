package vn.thanhtuanle.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import vn.thanhtuanle.auth.SecurityUserDetails;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtUtil {

    /** base64( PEM ) of the PKCS#8 RSA private key — signs every new token (RS256). */
    @Value("${application.security.jwt.rsa.private-key}")
    private String rsaPrivateKeyPem;

    /** base64( PEM ) of the X.509 RSA public key — verifies RS256 tokens. */
    @Value("${application.security.jwt.rsa.public-key}")
    private String rsaPublicKeyPem;

    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private String keyId;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    @PostConstruct
    void init() {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(
                    new PKCS8EncodedKeySpec(decodePem(rsaPrivateKeyPem, "PRIVATE KEY")));
            rsaPublicKey = (RSAPublicKey) kf.generatePublic(
                    new X509EncodedKeySpec(decodePem(rsaPublicKeyPem, "PUBLIC KEY")));
            byte[] fingerprint = MessageDigest.getInstance("SHA-256").digest(rsaPublicKey.getEncoded());
            keyId = HexFormat.of().formatHex(fingerprint).substring(0, 16);
        } catch (Exception e) {
            // Fail fast: an identity-service that cannot sign or verify tokens must not boot.
            throw new IllegalStateException(
                    "Invalid or missing RSA JWT keys (JWT_RSA_PRIVATE_KEY / JWT_RSA_PUBLIC_KEY)", e);
        }
        verifyKeypairMatches();
    }

    /**
     * Canary check: two well-formed RSA keys that are not actually a pair parse individually
     * without error, so the failure above would otherwise stay silent at boot and only surface
     * as a {@code SignatureException} on every request's signature check from then on. Signing
     * a throwaway token with the private key and verifying it with the public key catches that
     * mismatch here instead, while the app can still refuse to boot.
     */
    private void verifyKeypairMatches() {
        try {
            String canary = Jwts.builder()
                    .setSubject("jwt-keypair-canary")
                    .signWith(rsaPrivateKey, SignatureAlgorithm.RS256)
                    .compact();
            Jwts.parserBuilder().setSigningKey(rsaPublicKey).build().parseClaimsJws(canary);
        } catch (Exception e) {
            // No key material in the message: only a fixed, human-readable diagnosis.
            throw new IllegalStateException("RSA private and public keys are not a matching pair", e);
        }
    }

    /** kid stamped into every token header — first 16 hex chars of SHA-256(publicKey DER). */
    public String getKeyId() {
        return keyId;
    }

    /** Published through /.well-known/jwks.json so services can verify tokens without the private key. */
    public RSAPublicKey getPublicKey() {
        return rsaPublicKey;
    }

    /**
     * env value = base64(PEM file); strip the armor, decode the DER body.
     *
     * <p>The outer decode uses the MIME decoder, which ignores whitespace/newlines: operators
     * following the design doc's {@code base64 -w0} get an unwrapped blob, but plain
     * {@code base64} (no flag) line-wraps at 76 chars, and both must decode cleanly rather than
     * bricking boot with an error that reads like a corrupt key.
     */
    private static byte[] decodePem(String base64Pem, String type) {
        String pem = new String(java.util.Base64.getMimeDecoder().decode(base64Pem), StandardCharsets.UTF_8);
        String body = pem
                .replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return java.util.Base64.getDecoder().decode(body);
    }

    public String extractUsername(String jwtToken) {
        return extractClaims(jwtToken, Claims::getSubject);
    }

    /** The token's unique id (jti) — the key under which a revoked token is tracked in Redis. */
    public String extractJti(String jwtToken) {
        return extractClaims(jwtToken, Claims::getId);
    }

    /**
     * Milliseconds left until this token expires, clamped to 0. Used as the TTL when a token's
     * jti is parked in Redis so the entry self-evicts exactly when the token would have expired.
     */
    public long getRemainingTtlMillis(String jwtToken) {
        try {
            return Math.max(0, extractExpiration(jwtToken).getTime() - System.currentTimeMillis());
        } catch (ExpiredJwtException e) {
            return 0;
        }
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Self-contained access token: {@code uid} and {@code authorities} let every service authorise
     * the request from the token alone, with no per-request user lookup.
     */
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(OjJwtDecoders.UID_CLAIM, user.getId().toString());
        claims.put(OjJwtAuthenticationFilter.AUTHORITIES_CLAIM, new SecurityUserDetails(user).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList());
        return buildToken(claims, user, jwtExpiration);
    }

    public String generateRefreshToken(User userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extractClaims, User user, long expiration) {
        return Jwts
                .builder()
                .setHeaderParam(JwsHeader.KEY_ID, keyId)
                .setClaims(extractClaims)
                .setId(UUID.randomUUID().toString())
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(rsaPrivateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String email = extractUsername(token);
            return (email.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKeyResolver(signingKeyResolver)
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * RS256 only. The legacy HS256 dual-verify is gone (every HS256 token expired long ago), so a
     * token declaring any other alg — including the RS256->HS256 key-confusion trick — is refused.
     */
    private final SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            String alg = header.getAlgorithm();
            if (SignatureAlgorithm.RS256.getValue().equals(alg)) {
                return rsaPublicKey;
            }
            throw new UnsupportedJwtException("JWT algorithm not allowed: " + alg);
        }
    };
}
