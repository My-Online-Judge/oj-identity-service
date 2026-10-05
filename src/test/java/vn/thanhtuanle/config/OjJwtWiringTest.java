package vn.thanhtuanle.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.auth.JwksController;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The whole request path with real tokens: identity-service's JwtUtil mints them, oj-common's lenient
 * filter and validation rules verify them inside the real SecurityConfig chain. Only the key
 * lookup differs — the decoder is keyed with this service's public key directly, because MockMvc has
 * no running server for the JWKS URL to reach (JWKS itself is covered by JwksControllerTest and
 * the E2E run).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(OjJwtWiringTest.PublicKeyDecoder.class)
class OjJwtWiringTest {

    @TestConfiguration
    static class PublicKeyDecoder {
        @Bean
        JwtDecoder testJwtDecoder(JwtUtil jwtUtil) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtUtil.getPublicKey()).build();
            decoder.setJwtValidator(OjJwtDecoders.validator());
            return decoder;
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtUtil jwtUtil;
    @Value("${application.security.jwt.rsa.private-key}")
    private String privateKeyPem;

    private String tokenFor(String... permissions) {
        Role role = Role.builder().name("TESTER").permissions(new java.util.HashSet<>()).build();
        for (String name : permissions) {
            role.getPermissions().add(Permission.builder().name(name).build());
        }
        User user = User.builder().username("wiring-test").roles(Set.of(role)).build();
        user.setId(UUID.randomUUID());
        return jwtUtil.generateToken(user);
    }

    /** Signed by this service's real key but shaped like a pre-1a token (roles claim, no uid). */
    private String oldFormatToken(Date expiresAt) throws Exception {
        String pem = new String(Base64.getMimeDecoder().decode(privateKeyPem), StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        PrivateKey key = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        return Jwts.builder()
                .setSubject("wiring-test")
                .setId(UUID.randomUUID().toString())
                .claim("roles", java.util.List.of("ADMIN"))
                .setIssuedAt(new Date())
                .setExpiration(expiresAt)
                .signWith(key, SignatureAlgorithm.RS256)
                .compact();
    }

    @Test
    void aFreshTokenAuthorisesByItsAuthorities() throws Exception {
        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer " + tokenFor("role:read")))
                .andExpect(status().isOk());
    }

    @Test
    void aFreshTokenWithoutThePermissionIsForbidden() throws Exception {
        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer " + tokenFor("problem:create")))
                .andExpect(status().isForbidden());
    }

    @Test
    void anOldFormatTokenIsAnonymous_401OnProtected_200OnPublic() throws Exception {
        String old = oldFormatToken(new Date(System.currentTimeMillis() + 600_000));

        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer " + old))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get(JwksController.PATH).header("Authorization", "Bearer " + old))
                .andExpect(status().isOk());
    }

    @Test
    void anExpiredTokenLeftInTheCookieDoesNotBlockPublicEndpoints() throws Exception {
        // The cookie's age is fixed (1 day) while the token lifetime is configuration: it can ride expired.
        String expired = oldFormatToken(new Date(System.currentTimeMillis() - 3_600_000));

        mockMvc.perform(get(JwksController.PATH).cookie(new Cookie("accessToken", expired)))
                .andExpect(status().isOk());
    }

    @Test
    void theJwksEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(jwtUtil.getKeyId()));
    }
}
