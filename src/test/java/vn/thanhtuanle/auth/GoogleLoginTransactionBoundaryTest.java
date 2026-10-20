package vn.thanhtuanle.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.client.RestTemplate;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.user.UserRepository;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A Google sign-in holds no database transaction and no pooled connection while it waits for Google, and it audits the
 * attempt only after its short transaction, and with it the user's row lock, has ended. The audit (REQUIRES_NEW) needs
 * a connection of its own; taken under the lock, a busy pool would keep the user locked for up to Hikari's timeout.
 */
@SpringBootTest
@ActiveProfiles("test")
class GoogleLoginTransactionBoundaryTest {

    private static final ClientMeta META = new ClientMeta("10.0.0.7", "dev-7", "browser/7.0");
    private static final String NONCE = "boundary-nonce";

    @Autowired AuthService authService;
    @Autowired UserRepository userRepository;
    @Autowired DataSource dataSource;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    String googleClientId;

    /** Google's token endpoint. */
    @MockitoBean RestTemplate restTemplate;
    /** A mock, not the transactional bean: its answer sees the caller's own transaction and connections. */
    @MockitoBean LoginAttemptService loginAttemptService;

    private record DbState(boolean transactionActive, int connectionsInUse) {
    }

    private DbState dbState() {
        return new DbState(TransactionSynchronizationManager.isActualTransactionActive(),
                ((HikariDataSource) dataSource).getHikariPoolMXBean().getActiveConnections());
    }

    private String account(String googleId) {
        String username = "g_" + UUID.randomUUID().toString().substring(0, 8);
        userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .googleId(googleId)
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
        return username + "@example.com";
    }

    private ResponseEntity<ExchangeTokenResponse> googleTokenResponse(String email) {
        String idToken = new PlainJWT(new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com")
                .audience(googleClientId)
                // A Google account of its own per sign-in: an account linked by an earlier test is not found by it.
                .subject("google-sub-" + UUID.randomUUID())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("nonce", NONCE)
                .claim("email", email)
                .claim("email_verified", true)
                // A Workspace account: Google is authoritative for its address, so an existing account may be linked.
                .claim("hd", "example.com")
                .build()).serialize();
        return ResponseEntity.ok(ExchangeTokenResponse.builder().idToken(idToken).build());
    }

    private AtomicReference<DbState> recordStateWhileAuditing() {
        AtomicReference<DbState> whileAuditing = new AtomicReference<>();
        doAnswer(invocation -> {
            whileAuditing.set(dbState());
            return null;
        }).when(loginAttemptService).record(any(), any(), anyBoolean(), any());
        return whileAuditing;
    }

    @Test
    void theCallToGoogleHoldsNoTransactionOrConnection() {
        String email = account(null);
        AtomicReference<DbState> duringTheCall = new AtomicReference<>();
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenAnswer(invocation -> {
                    duringTheCall.set(dbState());
                    return googleTokenResponse(email);
                });

        AuthResponse tokens = authService.authenticateGoogleUser("code", "verifier", NONCE, META);

        assertThat(tokens.getAccessToken()).isNotNull();
        assertThat(duringTheCall.get()).isEqualTo(new DbState(false, 0));
    }

    @Test
    void aRefusalIsAuditedAfterTheUserLockIsReleased() {
        String email = account("google-sub-OTHER");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(googleTokenResponse(email));
        AtomicReference<DbState> whileAuditing = recordStateWhileAuditing();

        assertThatThrownBy(() -> authService.authenticateGoogleUser("code", "verifier", NONCE, META))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_ACCOUNT_MISMATCH));

        verify(loginAttemptService).record(email, META, false, "GOOGLE_ACCOUNT_MISMATCH");
        assertThat(whileAuditing.get()).isEqualTo(new DbState(false, 0));
    }

    @Test
    void aSuccessIsAuditedAfterTheUserLockIsReleased() {
        String email = account(null);
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(googleTokenResponse(email));
        AtomicReference<DbState> whileAuditing = recordStateWhileAuditing();

        authService.authenticateGoogleUser("code", "verifier", NONCE, META);

        verify(loginAttemptService).record(email, META, true, null);
        assertThat(whileAuditing.get()).isEqualTo(new DbState(false, 0));
    }
}
