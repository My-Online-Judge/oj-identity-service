package vn.thanhtuanle.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionRevokerTest {

    private static final UUID ALICE = UUID.fromString("11111111-2222-3333-4444-555555555555");

    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> values;

    private SessionRevoker revoker() {
        return new SessionRevoker(redis, 900_000L);
    }

    @AfterEach
    void endTransaction() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private static void finishTransaction(int status) {
        for (TransactionSynchronization sync : TransactionSynchronizationManager.getSynchronizations()) {
            if (status == TransactionSynchronization.STATUS_COMMITTED) {
                sync.afterCommit();
            }
            sync.afterCompletion(status);
        }
    }

    @Test
    void revokesOnlyAfterTheTransactionCommits() {
        when(redis.opsForValue()).thenReturn(values);
        TransactionSynchronizationManager.initSynchronization();
        long before = Instant.now().getEpochSecond();

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));
        verifyNoInteractions(redis);
        finishTransaction(TransactionSynchronization.STATUS_COMMITTED);

        ArgumentCaptor<String> revokedBefore = ArgumentCaptor.forClass(String.class);
        // TTL outlives the longest-lived token it covers: access TTL (15 min in this test) + 60s clock skew.
        verify(values).set(eq("oj:token:revoked-before:" + ALICE), revokedBefore.capture(),
                eq(Duration.ofSeconds(960)));
        // The cutoff is the second AFTER the change: iat is whole seconds, so a token minted earlier
        // in the same second must be revoked too.
        assertThat(Long.parseLong(revokedBefore.getValue()))
                .isBetween(before + 1, Instant.now().getEpochSecond() + 1);
    }

    @Test
    void aRolledBackChangeRevokesNothing() {
        TransactionSynchronizationManager.initSynchronization();

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));
        finishTransaction(TransactionSynchronization.STATUS_ROLLED_BACK);

        verifyNoInteractions(redis);
    }

    @Test
    void outsideATransactionItRevokesImmediately() {
        when(redis.opsForValue()).thenReturn(values);

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));

        verify(values).set(eq("oj:token:revoked-before:" + ALICE), anyString(), any(Duration.class));
    }

    @Test
    void aRedisFailureAfterCommitDoesNotFailTheRequest() {
        when(redis.opsForValue()).thenReturn(values);
        doThrow(new IllegalStateException("redis down")).when(values).set(anyString(), anyString(), any(Duration.class));

        assertThatCode(() -> revoker().revokeAccessTokensAfterCommit(List.of(ALICE))).doesNotThrowAnyException();
    }

    @Test
    void noUsersMeansNoWork() {
        revoker().revokeAccessTokensAfterCommit(List.of());

        verifyNoInteractions(redis);
    }
}
