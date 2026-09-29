package vn.thanhtuanle.common.util;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * All tokens are RS256 (+kid). T4-9b's time-boxed HS256 dual-verify was retired in sub-project 1:
 * a token declaring any other algorithm is refused.
 */
class JwtUtilRs256Test {

    // An HS256 secret in the old format (base64 of 64 bytes): what a pre-RS256 token was signed with.
    private static final String LEGACY_SECRET =
            Base64.getEncoder().encodeToString(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));

    private static KeyPair rsaPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    /** base64( PEM armor around base64(DER) ) — the exact env-var format the design mandates. */
    private static String pemBase64(String type, byte[] der) {
        String pem = "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Same PEM body as {@link #pemBase64}, but the OUTER encode is line-wrapped at 76 chars —
     * what plain {@code base64} (no {@code -w0}) produces, as opposed to the unwrapped
     * {@code base64 -w0} the design doc tells operators to use.
     */
    private static String pemBase64LineWrapped(String type, byte[] der) {
        String pem = "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Base64.getMimeEncoder(76, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private static JwtUtil newJwtUtil(KeyPair pair) {
        JwtUtil util = new JwtUtil();
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem", pemBase64("PRIVATE KEY", pair.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem", pemBase64("PUBLIC KEY", pair.getPublic().getEncoded()));
        ReflectionTestUtils.setField(util, "jwtExpiration", 900000L);
        ReflectionTestUtils.setField(util, "refreshExpiration", 259200000L);
        util.init();
        return util;
    }

    private static User alice() {
        User alice = User.builder().username("alice@example.com").build();
        alice.setId(java.util.UUID.fromString("11111111-2222-3333-4444-555555555555"));
        return alice;
    }

    /** Decode the JWS header (first dot-segment) as a UTF-8 JSON string. */
    private static String headerJson(String token) {
        return new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
    }

    @Test
    void rs256TokenRoundTrips() throws Exception {
        JwtUtil util = newJwtUtil(rsaPair());
        String token = util.generateToken(alice());
        assertThat(util.extractUsername(token)).isEqualTo("alice@example.com");
        assertThat(util.extractJti(token)).isNotBlank();
    }

    @Test
    void newTokensCarryRs256AndKidHeader() throws Exception {
        KeyPair pair = rsaPair();
        JwtUtil util = newJwtUtil(pair);
        String header = headerJson(util.generateToken(alice()));

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded());
        String expectedKid = HexFormat.of().formatHex(digest).substring(0, 16);

        assertThat(header).contains("\"alg\":\"RS256\"");
        assertThat(header).contains("\"kid\":\"" + expectedKid + "\"");
        assertThat(util.getKeyId()).isEqualTo(expectedKid);
    }

    @Test
    void refreshTokensAreAlsoRs256() throws Exception {
        JwtUtil util = newJwtUtil(rsaPair());
        assertThat(headerJson(util.generateRefreshToken(alice()))).contains("\"alg\":\"RS256\"");
    }


    @Test
    void hs256TokenIsAlwaysRejected() throws Exception {
        JwtUtil util = newJwtUtil(rsaPair()); // the HS256 dual-verify was retired in sub-project 1
        String legacyToken = Jwts.builder()
                .setSubject("alice@example.com")
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(LEGACY_SECRET)), SignatureAlgorithm.HS256)
                .compact();
        assertThatThrownBy(() -> util.extractUsername(legacyToken))
                .isInstanceOf(UnsupportedJwtException.class);
    }

    @Test
    void tokenSignedByDifferentRsaKeyRejected() throws Exception {
        JwtUtil trusted = newJwtUtil(rsaPair());
        JwtUtil attacker = newJwtUtil(rsaPair());
        String forged = attacker.generateToken(alice());
        assertThatThrownBy(() -> trusted.extractUsername(forged))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    void unsignedAlgNoneTokenRejected() throws Exception {
        JwtUtil util = newJwtUtil(rsaPair());
        String unsigned = Jwts.builder().setSubject("alice@example.com").compact(); // alg=none
        assertThatThrownBy(() -> util.extractUsername(unsigned))
                .isInstanceOf(UnsupportedJwtException.class);
    }

    @Test
    void algConfusion_hs256SignedWithPublicKeyBytes_rejected() throws Exception {
        KeyPair pair = rsaPair();
        JwtUtil util = newJwtUtil(pair);
        // Classic key-confusion attack: use the PUBLIC key bytes as an HMAC secret.
        String forged = Jwts.builder()
                .setSubject("alice@example.com")
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(pair.getPublic().getEncoded()), SignatureAlgorithm.HS256)
                .compact();
        // HS256 is not an allowed algorithm at all, so the token is refused before any key is chosen.
        assertThatThrownBy(() -> util.extractUsername(forged))
                .isInstanceOf(UnsupportedJwtException.class);
    }

    @Test
    void missingOrGarbageRsaKeysFailFast() {
        JwtUtil util = new JwtUtil();
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem", "bm90LWEta2V5");
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem", "bm90LWEta2V5");
        assertThatThrownBy(util::init).isInstanceOf(IllegalStateException.class);
    }

    /**
     * Task 1 review, Finding 1: the outer decode of the env value must tolerate a
     * line-wrapped base64 blob (what plain {@code base64}, without {@code -w0}, produces) —
     * not just the unwrapped form.
     */
    @Test
    void lineWrappedOuterBase64IsAccepted() throws Exception {
        KeyPair pair = rsaPair();
        JwtUtil util = new JwtUtil();
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem",
                pemBase64LineWrapped("PRIVATE KEY", pair.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem",
                pemBase64LineWrapped("PUBLIC KEY", pair.getPublic().getEncoded()));
        ReflectionTestUtils.setField(util, "jwtExpiration", 900000L);
        ReflectionTestUtils.setField(util, "refreshExpiration", 259200000L);
        util.init();

        String token = util.generateToken(alice());
        assertThat(util.extractUsername(token)).isEqualTo("alice@example.com");
    }

    /**
     * Task 1 review, Finding 2: a well-formed but mismatched private/public keypair must fail
     * fast at boot instead of booting cleanly and then failing every request's signature check.
     */
    @Test
    void mismatchedRsaKeypairFailsAtBoot() throws Exception {
        KeyPair pairA = rsaPair();
        KeyPair pairB = rsaPair();
        JwtUtil util = new JwtUtil();
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem",
                pemBase64("PRIVATE KEY", pairA.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem",
                pemBase64("PUBLIC KEY", pairB.getPublic().getEncoded()));
        ReflectionTestUtils.setField(util, "jwtExpiration", 900000L);
        ReflectionTestUtils.setField(util, "refreshExpiration", 259200000L);

        assertThatThrownBy(util::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a matching pair");
    }

    /**
     * Cheap regression guard: whatever the mismatched-keypair message says, it must never
     * echo key material (base64 of the PEM, or the raw PEM body) back to the caller/logs.
     */
    @Test
    void mismatchedKeypairMessageLeaksNoKeyMaterial() throws Exception {
        KeyPair pairA = rsaPair();
        KeyPair pairB = rsaPair();
        String privatePem = pemBase64("PRIVATE KEY", pairA.getPrivate().getEncoded());
        String publicPem = pemBase64("PUBLIC KEY", pairB.getPublic().getEncoded());

        JwtUtil util = new JwtUtil();
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem", privatePem);
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem", publicPem);
        ReflectionTestUtils.setField(util, "jwtExpiration", 900000L);
        ReflectionTestUtils.setField(util, "refreshExpiration", 259200000L);

        assertThatThrownBy(util::init)
                .isInstanceOf(IllegalStateException.class)
                .satisfies(ex -> {
                    String message = ex.getMessage();
                    assertThat(message).doesNotContain(privatePem);
                    assertThat(message).doesNotContain(publicPem);
                    // Also guard against leaking a raw base64 fragment of the DER itself.
                    assertThat(message).doesNotContain(
                            Base64.getEncoder().encodeToString(pairA.getPrivate().getEncoded()).substring(0, 40));
                });
    }

    /**
     * Sub-project 1a: the access token is self-contained — services authorise from uid +
     * authorities alone. authorities = role names + permission names, exactly what
     * SecurityUserDetails grants, sorted for a stable token.
     */
    @Test
    void accessTokenCarriesUidAndTheUsersAuthorities() throws Exception {
        JwtUtil util = newJwtUtil(rsaPair());
        User bob = alice();
        Role moderator = Role.builder().name("MODERATOR")
                .permissions(Set.of(Permission.builder().name("problem:update").build(),
                        Permission.builder().name("problem:create").build()))
                .build();
        bob.setRoles(Set.of(moderator));

        String token = util.generateToken(bob);

        String uid = util.extractClaims(token, c -> c.get("uid", String.class));
        List<Object> authorities = util.extractClaims(token, c -> c.get("authorities", List.class));
        Boolean hasRolesClaim = util.extractClaims(token, c -> c.containsKey("roles"));

        assertThat(uid).isEqualTo("11111111-2222-3333-4444-555555555555");
        assertThat(authorities).containsExactly("MODERATOR", "problem:create", "problem:update");
        assertThat(hasRolesClaim).as("the unused roles claim is gone").isFalse();
    }

    @Test
    void publicKeyIsExposedForTheJwksEndpoint() throws Exception {
        KeyPair pair = rsaPair();
        assertThat(newJwtUtil(pair).getPublicKey()).isEqualTo(pair.getPublic());
    }
}
