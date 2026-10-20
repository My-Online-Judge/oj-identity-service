package vn.thanhtuanle.auth;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.error.AppException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Reads the Google identity out of the id token that Google's token endpoint returned for our authorization code.
 *
 * <p>The signature is not checked: the token comes straight from Google's token endpoint over TLS, in the response to
 * our own authenticated request, so TLS already proves the issuer (OIDC Core §3.1.3.7 item 6). The claims are checked:
 * issuer, audience, expiry, the nonce of this sign-in attempt, and a subject and email. Any failure is
 * {@link ErrorCode#GOOGLE_ID_TOKEN_INVALID}.
 */
@Component
@Slf4j
public class GoogleIdTokenVerifier {

    static final Set<String> ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");
    static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private final String clientId;
    private final Clock clock;

    public GoogleIdTokenVerifier(
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId, Clock clock) {
        this.clientId = clientId;
        this.clock = clock;
    }

    /** Who signed in. {@code emailVerified} is Google's {@code email_verified}; false when absent. */
    public record GoogleIdentity(String sub, String email, boolean emailVerified, String name, String picture) {
    }

    public GoogleIdentity verify(String idToken, String expectedNonce) {
        JWTClaimsSet claims = claimsOf(idToken);
        try {
            if (claims.getIssuer() == null || !ISSUERS.contains(claims.getIssuer())) {
                throw invalid("issuer");
            }
            List<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(clientId)) {
                throw invalid("audience");
            }
            Date expiry = claims.getExpirationTime();
            if (expiry == null || !expiry.toInstant().isAfter(clock.instant().minus(CLOCK_SKEW))) {
                throw invalid("expiry");
            }
            if (!sameNonce(claims.getStringClaim("nonce"), expectedNonce)) {
                throw invalid("nonce");
            }
            String sub = claims.getSubject();
            String email = claims.getStringClaim("email");
            if (isBlank(sub) || isBlank(email)) {
                throw invalid("subject or email missing");
            }
            return new GoogleIdentity(sub, email, isTrue(claims.getClaim("email_verified")),
                    claims.getStringClaim("name"), claims.getStringClaim("picture"));
        } catch (AppException e) {
            throw e;
        } catch (Exception e) {
            // A claim of the wrong type (getStringClaim throws ParseException).
            throw invalid("malformed claim");
        }
    }

    private JWTClaimsSet claimsOf(String idToken) {
        if (idToken == null) {
            throw invalid("no id token");
        }
        try {
            JWT jwt = JWTParser.parse(idToken);
            if (!(jwt instanceof SignedJWT || jwt instanceof PlainJWT)) {
                throw invalid("neither signed nor plain");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims == null) {
                throw invalid("no claims");
            }
            return claims;
        } catch (AppException e) {
            throw e;
        } catch (Exception e) {
            throw invalid("unparseable");
        }
    }

    /** Constant-time compare, like the state check. */
    private static boolean sameNonce(String actual, String expected) {
        return actual != null && expected != null && MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }

    /** Google sends {@code email_verified} as a JSON boolean, and has sent it as the string {@code "true"}. */
    private static boolean isTrue(Object emailVerified) {
        return Boolean.TRUE.equals(emailVerified) || "true".equals(emailVerified);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** The reason goes to the log only: never the token or its claims. */
    private static AppException invalid(String reason) {
        log.warn("Google id token refused: {}", reason);
        return new AppException(ErrorCode.GOOGLE_ID_TOKEN_INVALID);
    }
}
