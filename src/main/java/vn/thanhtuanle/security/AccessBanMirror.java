package vn.thanhtuanle.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import vn.thanhtuanle.oj.common.redis.RedisKeys;
import vn.thanhtuanle.common.enums.BanType;
import vn.thanhtuanle.entity.AccessBan;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Redis mirror of t_access_bans for O(1) lookup on every request (multi-instance safe).
 * One key per ban (oj:ban:ip:&lt;v&gt; / oj:ban:device:&lt;v&gt;) — a temporary ban's key carries a
 * matching TTL so it self-evicts. Postgres stays the source of truth; the mirror is
 * rebuilt at boot and updated synchronously on CRUD. Redis being down fails OPEN.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AccessBanMirror {

    private final StringRedisTemplate redis;

    public void add(AccessBan ban) {
        Duration ttl = ban.getExpiresAt() == null ? null
                : Duration.between(LocalDateTime.now(), ban.getExpiresAt());
        if (ttl != null && (ttl.isZero() || ttl.isNegative())) {
            return; // already expired — nothing to enforce
        }
        String key = key(ban.getType(), ban.getValue());
        try {
            if (ttl == null) {
                redis.opsForValue().set(key, "1");
            } else {
                redis.opsForValue().set(key, "1", ttl);
            }
        } catch (Exception e) {
            log.warn("Ban mirror unavailable, {} not mirrored: {}", key, e.getMessage());
        }
    }

    public void remove(BanType type, String value) {
        try {
            redis.delete(key(type, value));
        } catch (Exception e) {
            log.warn("Ban mirror unavailable, {} not removed: {}", key(type, value), e.getMessage());
        }
    }


    static String key(BanType type, String value) {
        return RedisKeys.accessBan(type.name(), value);
    }
}
