package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenBlocklistTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOps;

    @InjectMocks
    private TokenBlocklist blocklist;

    @Test
    void block_storesJtiKeyWithTtlEqualToRemainingLifetime() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        blocklist.block("jti-123", 900_000L);

        // The key self-evicts exactly when the token would have expired.
        verify(valueOps).set(eq("oj:token:blocklist:jti-123"), anyString(), eq(Duration.ofMillis(900_000L)));
    }

    @Test
    void block_withNonPositiveTtl_isANoOp() {
        blocklist.block("jti-expired", 0L);

        // An already-expired token needs no blocklist entry — the filter's expiry check rejects it.
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void block_withNullJti_isANoOp() {
        blocklist.block(null, 900_000L);

        verifyNoInteractions(redisTemplate);
    }
}
