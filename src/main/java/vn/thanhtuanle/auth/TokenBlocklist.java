package vn.thanhtuanle.auth;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.oj.common.redis.RedisKeys;

import java.time.Duration;

/**
 * Redis-backed revocation list for access tokens, keyed by the token's {@code jti}.
 *
 * <p>On logout a token's jti is parked here with a TTL equal to the token's remaining lifetime, so
 * the entry self-evicts exactly when the token would have expired anyway — the list never grows
 * unbounded. The api-gateway reads it on every request and strips a blocklisted token, which is what
 * makes logout actually invalidate a token that is otherwise still signature-valid.
 */
@Component
@Slf4j
public class TokenBlocklist {

    private final StringRedisTemplate redisTemplate;
    private final Counter fallbacks;

    public TokenBlocklist(StringRedisTemplate redisTemplate, MeterRegistry registry) {
        this.redisTemplate = redisTemplate;
        this.fallbacks = Counter.builder("oj.redis.fallback")
                .description("Requests or work that went on without Redis because a Redis call failed (fail-open)")
                .tag("lookup", "logout")
                .register(registry);
    }

    /**
     * Revoke {@code jti} until {@code ttlMillis} from now. A null jti or a non-positive TTL (an
     * already-expired token) is a no-op — the filter's own expiry check already rejects those.
     *
     * <p>Fails open: with Redis down the logout still deletes every session in the database (which needs no Redis);
     * only this access token stays usable until it expires (at most the access-token TTL).
     */
    public void block(String jti, long ttlMillis) {
        if (jti == null || ttlMillis <= 0) {
            return;
        }
        try {
            redisTemplate.opsForValue().set(RedisKeys.tokenBlocklist(jti), "1", Duration.ofMillis(ttlMillis));
        } catch (RuntimeException e) {
            fallbacks.increment();
            log.warn("Could not blocklist the access token at logout (Redis unavailable): {}", e.getMessage());
        }
    }

}
