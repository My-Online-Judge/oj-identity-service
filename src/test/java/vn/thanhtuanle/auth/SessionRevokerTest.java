package vn.thanhtuanle.auth;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.thanhtuanle.oj.common.redis.RedisKeys;
import vn.thanhtuanle.oj.common.security.RevocationCutoffs;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionRevokerTest {

    private static final UUID ALICE = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final Instant NOW = Instant.parse("2026-10-21T01:02:03.456Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneId.of("Asia/Ho_Chi_Minh"));

    @Mock StringRedisTemplate redis;
    @Mock ValueOperations<String, String> values;

    private SessionRevoker revoker() {
        return new SessionRevoker(redis, 900_000L, Duration.ofHours(25), CLOCK);
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

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));
        verifyNoInteractions(redis);
        finishTransaction(TransactionSynchronization.STATUS_COMMITTED);

        // The marker outlives every token it may cover, the 1-day access tokens minted before sub-project 12 included.
        // The cutoff is the second AFTER the change: iat is whole seconds, so a token minted earlier
        // in the same second must be revoked too.
        verify(values).set("oj:token:revoked-before:" + ALICE, String.valueOf(NOW.getEpochSecond() + 1),
                Duration.ofHours(25));
    }

    /**
     * Both cutoffs, from one instant and with one TTL: the gateway of this release compares a token's iat_ms with the
     * millisecond one, an older gateway (and a token without iat_ms) keeps the whole-second one.
     */
    @Test
    void writesTheSecondAndTheMillisecondCutoff() {
        when(redis.opsForValue()).thenReturn(values);

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));

        verify(values).set(RedisKeys.tokenRevokedBefore(ALICE), RevocationCutoffs.secondsMarker(NOW),
                Duration.ofHours(25));
        verify(values).set(RedisKeys.tokenRevokedBeforeMillis(ALICE), RevocationCutoffs.millisMarker(NOW),
                Duration.ofHours(25));
        verifyNoMoreInteractions(values);
        assertThat(RedisKeys.tokenRevokedBeforeMillis(ALICE)).isEqualTo("oj:token:revoked-before-ms:" + ALICE);
        assertThat(RevocationCutoffs.millisMarker(NOW)).isEqualTo(String.valueOf(NOW.toEpochMilli() + 1));
    }

    @Test
    void aRolledBackChangeWritesNeither() {
        TransactionSynchronizationManager.initSynchronization();

        revoker().revokeAccessTokensAfterCommit(List.of(ALICE));
        finishTransaction(TransactionSynchronization.STATUS_ROLLED_BACK);

        // Neither the seconds key nor the milliseconds key: nothing reaches Redis at all.
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

    @Test
    void aMarkerNeverExpiresBeforeTheAccessTokensItCovers() {
        when(redis.opsForValue()).thenReturn(values);

        new SessionRevoker(redis, 900_000L, Duration.ofMinutes(1), CLOCK).revokeAccessTokensAfterCommit(List.of(ALICE));

        // Configured shorter than an access token lives: the access TTL (15 min here) + 60 s clock skew still holds.
        verify(values).set(eq("oj:token:revoked-before:" + ALICE), anyString(), eq(Duration.ofSeconds(960)));
    }

    /** The revoker as the application builds it: Spring Boot's conversions, this configuration, a mocked Redis. */
    private ApplicationContextRunner application() {
        return new ApplicationContextRunner()
                .withInitializer(context -> context.getBeanFactory()
                        .setConversionService(ApplicationConversionService.getSharedInstance()))
                .withPropertyValues("application.security.jwt.expiration=900000")
                .withBean(StringRedisTemplate.class, () -> redis)
                .withBean(Clock.class, () -> CLOCK)
                .withBean(SessionRevoker.class);
    }

    private Duration markerTtlOf(SessionRevoker revoker) {
        org.mockito.Mockito.clearInvocations(values);
        revoker.revokeAccessTokensAfterCommit(List.of(ALICE));
        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(values).set(eq("oj:token:revoked-before:" + ALICE), anyString(), ttl.capture());
        return ttl.getValue();
    }

    @Test
    void theMarkerTtlIsOjSessionRevocationMarkerTtl_settableAsOJ_SESSION_REVOCATION_MARKER_TTL_and25hByDefault() {
        when(redis.opsForValue()).thenReturn(values);

        application().run(context ->
                assertThat(markerTtlOf(context.getBean(SessionRevoker.class))).isEqualTo(Duration.ofHours(25)));
        application().withPropertyValues("oj.session.revocation-marker-ttl=2h").run(context ->
                assertThat(markerTtlOf(context.getBean(SessionRevoker.class))).isEqualTo(Duration.ofHours(2)));
        // How .env.identity sets it: an environment variable, bound the way Spring Boot binds them.
        application()
                .withInitializer(context -> {
                    ConfigurableEnvironment environment = context.getEnvironment();
                    environment.getPropertySources().replace(
                            StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                            new SystemEnvironmentPropertySource(
                                    StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                                    Map.of("OJ_SESSION_REVOCATION_MARKER_TTL", "26h")));
                    ConfigurationPropertySources.attach(environment);
                })
                .run(context ->
                        assertThat(markerTtlOf(context.getBean(SessionRevoker.class))).isEqualTo(Duration.ofHours(26)));
    }
}
