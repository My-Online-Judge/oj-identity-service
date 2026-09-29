package vn.thanhtuanle.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.thanhtuanle.common.util.JwtUtil;

import java.util.Map;

/**
 * Publishes the token-signing public key (RFC 7517 JWK Set) so services verify access tokens
 * without ever holding the private key. Internal to oj-net: the gateway does not route this path.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    public static final String PATH = "/.well-known/jwks.json";

    private final JwtUtil jwtUtil;

    @GetMapping(value = PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        RSAKey key = new RSAKey.Builder(jwtUtil.getPublicKey())
                .keyID(jwtUtil.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new JWKSet(key).toJSONObject();
    }
}
