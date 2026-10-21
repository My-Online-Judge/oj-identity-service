package vn.thanhtuanle.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.redis.RedisKeys;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;
import vn.thanhtuanle.oj.common.security.RevocationCutoffs;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A logout followed by a new login within the same second: the token the login mints is kept, a token minted before
 * the logout is not. Identity's real token minting and revocation markers, with {@link RevocationCutoffs#revoked}
 * standing in for the gateway's check.
 */
class SameSecondLoginTest {

    /** Mid-second, so 300 ms either side stays in the same whole second. */
    private static final Instant LOGOUT = Instant.parse("2026-10-21T01:02:03.500Z");
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    private final UUID userId = UUID.randomUUID();
    private final Map<String, String> redisValues = new HashMap<>();
    private KeyPair pair;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();

        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        doAnswer(call -> redisValues.put(call.getArgument(0), call.getArgument(1)))
                .when(values).set(anyString(), anyString(), any(Duration.class));
        new SessionRevoker(redis, 900_000L, Duration.ofHours(25), Clock.fixed(LOGOUT, ZONE))
                .revokeAccessTokensAfterCommit(List.of(userId));
    }

    private JwtUtil jwtUtilAt(Instant now) {
        JwtUtil util = new JwtUtil(Clock.fixed(now, ZONE));
        ReflectionTestUtils.setField(util, "rsaPrivateKeyPem", pemBase64("PRIVATE KEY", pair.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(util, "rsaPublicKeyPem", pemBase64("PUBLIC KEY", pair.getPublic().getEncoded()));
        ReflectionTestUtils.setField(util, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(util, "refreshExpiration", 259_200_000L);
        ReflectionTestUtils.invokeMethod(util, "init");
        return util;
    }

    private static String pemBase64(String type, byte[] der) {
        String pem = "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder().encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private User user() {
        User user = User.builder().username("alice").build();
        user.setId(userId);
        return user;
    }

    /** What the gateway decides for this token, from its iat and iat_ms claims and the two markers in Redis. */
    private boolean gatewayRevokes(String token) throws Exception {
        JsonNode claims = new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        return RevocationCutoffs.revoked(claims.get("iat").asLong(), claims.path(OjJwtDecoders.IAT_MS_CLAIM).asLong(0),
                redisValues.get(RedisKeys.tokenRevokedBefore(userId)),
                redisValues.get(RedisKeys.tokenRevokedBeforeMillis(userId)));
    }

    @Test
    void aLoginAfterALogoutInTheSameSecondKeepsItsToken() throws Exception {
        String token = jwtUtilAt(LOGOUT.plusMillis(300)).generateToken(user());

        assertThat(gatewayRevokes(token)).isFalse();
    }

    @Test
    void aTokenMintedBeforeTheLogoutIsRevoked() throws Exception {
        String token = jwtUtilAt(LOGOUT.minusMillis(300)).generateToken(user());

        assertThat(gatewayRevokes(token)).isTrue();
    }

    /** A token without iat_ms (minted before this release) is judged by its whole second, as before. */
    @Test
    void aTokenWithoutIatMillisKeepsTheWholeSecondRule() throws Exception {
        String withoutIatMillis = jwtUtilAt(LOGOUT.plusMillis(300)).generateRefreshToken(user());

        assertThat(gatewayRevokes(withoutIatMillis)).isTrue();
    }
}
