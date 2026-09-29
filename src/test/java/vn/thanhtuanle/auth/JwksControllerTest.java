package vn.thanhtuanle.auth;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.common.util.JwtUtil;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwksControllerTest {

    private static String pemBase64(String type, byte[] der) {
        String pem = "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void publishesTheSigningKeyUnderItsKidAndNothingPrivate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        JwtUtil jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "rsaPrivateKeyPem", pemBase64("PRIVATE KEY", pair.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(jwtUtil, "rsaPublicKeyPem", pemBase64("PUBLIC KEY", pair.getPublic().getEncoded()));
        ReflectionTestUtils.invokeMethod(jwtUtil, "init");

        JWKSet set = JWKSet.parse(new JwksController(jwtUtil).jwks());

        assertThat(set.getKeys()).hasSize(1);
        JWK key = set.getKeys().get(0);
        assertThat(key.getKeyID()).isEqualTo(jwtUtil.getKeyId());
        assertThat(key.getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(key.getKeyUse().identifier()).isEqualTo("sig");
        assertThat(key.isPrivate()).as("never the private key").isFalse();
        assertThat(((RSAKey) key).toRSAPublicKey()).isEqualTo(pair.getPublic());
    }
}
