package vn.thanhtuanle.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.redis.RedisKeys;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;
import vn.thanhtuanle.oj.common.security.RevocationCutoffs;
import vn.thanhtuanle.repository.TokenRepository;
import vn.thanhtuanle.user.UserRepository;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A role change that commits while a refresh is in flight, between the refresh's read of the user's roles and its
 * mint: the minted access token still carries the old roles, so the millisecond cutoff the change writes must revoke
 * it. Identity's real token minting, refresh and revocation markers, with {@link RevocationCutoffs#revoked} standing in
 * for the gateway's check. A role change takes no user-row lock, so nothing else serialises it with the refresh.
 */
class RoleChangeDuringRefreshTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "agent");
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    /** Mid-second, so the whole exchange stays in one whole second. Real time: the refresh token must not expire. */
    private final Instant start = Instant.now().truncatedTo(ChronoUnit.SECONDS).plusMillis(500);
    private final MutableClock clock = new MutableClock(start);
    private final Map<String, String> redisValues = new HashMap<>();
    private final UUID userId = UUID.randomUUID();

    private final UserRepository userRepository = mock(UserRepository.class);
    private final TokenRepository tokenRepository = mock(TokenRepository.class);
    private JwtUtil jwtUtil;
    private SessionRevoker sessionRevoker;
    private AuthService authService;

    /** A clock the test moves forward, shared by the minting, the refresh and the revocation. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZONE;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        jwtUtil = new JwtUtil(clock);
        ReflectionTestUtils.setField(jwtUtil, "rsaPrivateKeyPem", pemBase64("PRIVATE KEY", pair.getPrivate().getEncoded()));
        ReflectionTestUtils.setField(jwtUtil, "rsaPublicKeyPem", pemBase64("PUBLIC KEY", pair.getPublic().getEncoded()));
        ReflectionTestUtils.setField(jwtUtil, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(jwtUtil, "refreshExpiration", 259_200_000L);
        ReflectionTestUtils.invokeMethod(jwtUtil, "init");

        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        doAnswer(call -> redisValues.put(call.getArgument(0), call.getArgument(1)))
                .when(values).set(anyString(), anyString(), any(Duration.class));
        sessionRevoker = new SessionRevoker(redis, 900_000L, Duration.ofHours(25), clock);

        // Only the collaborators the refresh path uses; the rest are not reached.
        authService = new AuthService(userRepository, jwtUtil, tokenRepository, null, null, null, null, null, null,
                null, sessionRevoker, clock, null, null, null, null);
    }

    private static String pemBase64(String type, byte[] der) {
        String pem = "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder().encodeToString(der)
                + "\n-----END " + type + "-----\n";
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    /** What the gateway decides for this token, from its iat and iat_ms claims and the two markers in Redis. */
    private boolean gatewayRevokes(String token) throws Exception {
        JsonNode claims = new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        return RevocationCutoffs.revoked(claims.get("iat").asLong(), claims.path(OjJwtDecoders.IAT_MS_CLAIM).asLong(0),
                redisValues.get(RedisKeys.tokenRevokedBefore(userId)),
                redisValues.get(RedisKeys.tokenRevokedBeforeMillis(userId)));
    }

    @Test
    void aRoleChangeCommittedBetweenTheStateReadAndTheMintRevokesTheMintedToken() throws Exception {
        User user = User.builder().username("alice").status(CommonStatus.ACTIVE.getValue()).roles(new HashSet<>())
                .build();
        user.setId(userId);
        String refreshToken = jwtUtil.generateRefreshToken(user);
        Token stored = Token.builder().token(TokenHasher.sha256Hex(refreshToken)).tokenType(TokenType.REFRESH)
                .user(user).build();
        stored.setId(UUID.randomUUID());
        when(tokenRepository.findByToken(TokenHasher.sha256Hex(refreshToken))).thenReturn(Optional.of(stored));
        when(tokenRepository.markRotated(eq(stored.getId()), any())).thenReturn(1);
        when(userRepository.lockById(userId)).thenAnswer(invocation -> {
            // The refresh has read the user's roles. The role change commits 1 ms later and writes its cutoffs; the
            // refresh then mints 2 ms after that.
            clock.set(start.plusMillis(1));
            sessionRevoker.revokeAccessTokensAfterCommit(List.of(userId));
            clock.set(start.plusMillis(3));
            return Optional.of(user);
        });

        AuthResponse tokens = authService.refreshAccessToken(refreshToken, META);

        assertThat(tokens.getAccessToken()).isNotNull();
        assertThat(gatewayRevokes(tokens.getAccessToken())).isTrue();
    }
}
