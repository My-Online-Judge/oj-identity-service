package vn.thanhtuanle.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.error.AppException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GoogleIdTokenVerifierTest {

    private static final String CLIENT_ID = "client-123.apps.googleusercontent.com";
    private static final String NONCE = "nonce-abc";
    private static final Instant NOW = Instant.parse("2026-10-20T05:00:00Z");

    private final GoogleIdTokenVerifier verifier =
            new GoogleIdTokenVerifier(CLIENT_ID, Clock.fixed(NOW, ZoneOffset.UTC));

    /** The claims Google's token endpoint returns for a verified account, valid for an hour. */
    private static JWTClaimsSet.Builder googleClaims() {
        return new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com")
                .audience(CLIENT_ID)
                .subject("google-sub-1")
                .issueTime(Date.from(NOW.minusSeconds(5)))
                .expirationTime(Date.from(NOW.plusSeconds(3600)))
                .claim("nonce", NONCE)
                .claim("email", "alice@example.com")
                .claim("email_verified", true)
                .claim("name", "Alice")
                .claim("picture", "https://example.com/alice.png");
    }

    private static String plain(JWTClaimsSet.Builder claims) {
        return new PlainJWT(claims.build()).serialize();
    }

    private void assertRejected(String idToken) {
        assertThatThrownBy(() -> verifier.verify(idToken, NONCE))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ID_TOKEN_INVALID));
    }

    @Test
    void acceptsAValidToken() {
        GoogleIdTokenVerifier.GoogleIdentity identity = verifier.verify(plain(googleClaims()), NONCE);

        assertThat(identity).isEqualTo(new GoogleIdTokenVerifier.GoogleIdentity(
                "google-sub-1", "alice@example.com", true, "Alice", "https://example.com/alice.png"));
    }

    @Test
    void rejectsWrongNonce() {
        assertRejected(plain(googleClaims().claim("nonce", "someone-elses-nonce")));
        assertRejected(plain(googleClaims().claim("nonce", null)));
    }

    @Test
    void rejectsWrongAudience() {
        assertRejected(plain(googleClaims().audience("another-client.apps.googleusercontent.com")));
    }

    @Test
    void rejectsWrongIssuer() {
        assertRejected(plain(googleClaims().issuer("https://evil.example.com")));
    }

    @Test
    void rejectsExpired() {
        // 60 s of clock skew is tolerated, no more.
        assertThat(verifier.verify(plain(googleClaims().expirationTime(Date.from(NOW.minusSeconds(59)))), NONCE))
                .isNotNull();
        assertRejected(plain(googleClaims().expirationTime(Date.from(NOW.minusSeconds(61)))));
        assertRejected(plain(googleClaims().expirationTime(null)));
    }

    @Test
    void rejectsAMissingSubjectOrEmail_andGarbage() {
        assertRejected(plain(googleClaims().subject(" ")));
        assertRejected(plain(googleClaims().claim("email", null)));
        assertRejected("not-a-jwt");
        assertRejected(null);
    }

    @Test
    void parsesASignedToken() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("google-key").generate();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                googleClaims().issuer("accounts.google.com").build());
        jwt.sign(new RSASSASigner(key));

        GoogleIdTokenVerifier.GoogleIdentity identity = verifier.verify(jwt.serialize(), NONCE);

        assertThat(identity.sub()).isEqualTo("google-sub-1");
        assertThat(identity.emailVerified()).isTrue();
    }

    @Test
    void emailVerifiedAsString() {
        assertThat(verifier.verify(plain(googleClaims().claim("email_verified", "true")), NONCE).emailVerified())
                .isTrue();
        assertThat(verifier.verify(plain(googleClaims().claim("email_verified", "false")), NONCE).emailVerified())
                .isFalse();
        assertThat(verifier.verify(plain(googleClaims().claim("email_verified", false)), NONCE).emailVerified())
                .isFalse();
        assertThat(verifier.verify(plain(googleClaims().claim("email_verified", null)), NONCE).emailVerified())
                .isFalse();
    }
}
