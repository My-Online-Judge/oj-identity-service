package vn.thanhtuanle.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.thanhtuanle.oj.common.redis.RedisKeys;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Revokes every access token a user holds by recording a cutoff ({@link RedisKeys#tokenRevokedBefore});
 * the gateway strips any token whose {@code iat} is older than it.
 * A per-user timestamp — not a jti list from {@code t_tokens} — also catches tokens that a refresh
 * already replaced but that are still unexpired.
 *
 * <p>Access tokens carry authorities and account status no longer lives in a per-request lookup,
 * so this is what makes disabling a user or changing their permissions take effect at once: the
 * portal gets a 401, refreshes, and receives a token minted from the new state.
 */
@Component
@Slf4j
public class SessionRevoker {

    /** Same skew the verifiers allow, so a marker never expires while a covered token is valid. */
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private final StringRedisTemplate redis;
    private final Duration markerTtl;

    public SessionRevoker(StringRedisTemplate redis,
                          @Value("${application.security.jwt.expiration}") long accessTokenTtlMillis) {
        this.redis = redis;
        this.markerTtl = Duration.ofMillis(accessTokenTtlMillis).plus(CLOCK_SKEW);
    }

    /**
     * Revoke these users' access tokens once the surrounding transaction commits — a mutation that
     * rolls back must not log anyone out. Outside a transaction it revokes immediately.
     */
    public void revokeAccessTokensAfterCommit(Collection<UUID> userIds) {
        if (userIds.isEmpty()) {
            return;
        }
        List<UUID> ids = List.copyOf(userIds);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    revokeNow(ids);
                }
            });
        } else {
            revokeNow(ids);
        }
    }

    private void revokeNow(List<UUID> ids) {
        // iat has whole-second precision: a token minted earlier in this very second looks the same as
        // one minted just after, so the cutoff is the NEXT second and the whole current second is
        // revoked. (Otherwise a client refreshing in a tight loop would keep a pre-change token.) A
        // refresh landing in this same second is revoked too; the portal then logs that user out once.
        String revokedBefore = String.valueOf(Instant.now().getEpochSecond() + 1);
        try {
            for (UUID id : ids) {
                redis.opsForValue().set(RedisKeys.tokenRevokedBefore(id), revokedBefore, markerTtl);
            }
        } catch (RuntimeException e) {
            // The change is already committed; failing the request now would only hide that. Tokens
            // minted before it stay usable until they expire (at most the access-token TTL).
            log.error("Could not revoke access tokens for {} user(s): {}", ids.size(), e.getMessage());
        }
    }
}
