package vn.thanhtuanle.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.auth.dto.AuthResponse;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.UserRepository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Token mutations of one user are serialised by a lock on the user's row, on real Postgres. Without it a successor
 * minted by a concurrent rotation is invisible to a delete-all running at the same time, and survives reuse
 * detection, logout and login.
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class TokenMutationRaceTest {

    private static final String PASSWORD = "Secret123";
    private static final ClientMeta META = new ClientMeta("10.0.0.1", "dev-1", "race/1.0");

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void identityDb(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.flyway.enabled", () -> "true");
    }

    @Autowired AuthService authService;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired JdbcTemplate jdbc;

    @MockitoSpyBean JwtUtil jwtUtil;
    @MockitoBean LoginRateLimiter loginRateLimiter;
    @MockitoBean SessionRevoker sessionRevoker;
    @MockitoBean TokenBlocklist tokenBlocklist;
    /** Google's token endpoint. */
    @MockitoBean RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    String googleClientId;

    private final ExecutorService first = Executors.newSingleThreadExecutor(r -> new Thread(r, "race-first"));
    private final ExecutorService second = Executors.newSingleThreadExecutor(r -> new Thread(r, "race-second"));

    private record Session(UUID userId, String refreshToken) {
    }

    @AfterEach
    void stopThreads() {
        first.shutdownNow();
        second.shutdownNow();
    }

    private Session login() {
        String username = "race_" + UUID.randomUUID().toString().substring(0, 8);
        User user = userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode(PASSWORD))
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
        AuthResponse tokens = authService.authenticateWithPassword(username, PASSWORD, META);
        return new Session(user.getId(), tokens.getRefreshToken());
    }

    private Connection connect() throws Exception {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    /** Waits until this many backends of the test database wait for a lock. */
    private void awaitLockWaiters(int count) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        try (Connection connection = connect();
             PreparedStatement waiting = connection.prepareStatement(
                     "select count(*) from pg_stat_activity where datname = current_database() and wait_event_type = 'Lock'")) {
            while (System.nanoTime() < deadline) {
                try (ResultSet rs = waiting.executeQuery()) {
                    rs.next();
                    if (rs.getInt(1) >= count) {
                        return;
                    }
                }
                Thread.sleep(20);
            }
        }
        throw new AssertionError("fewer than " + count + " backends ever waited for a lock");
    }

    /** "type rotated?" for each token row of the user. */
    private List<String> rowsOf(UUID userId) {
        return jdbc.queryForList(
                "select token_type || ' ' || (rotated_at is not null) from t_tokens where user_id = ? order by 1",
                String.class, userId);
    }

    @Test
    void twoRefreshesWithTheSameTokenMintExactlyOneSuccessor() throws Exception {
        Session session = login();
        Future<AuthResponse> a;
        Future<AuthResponse> b;
        // Hold the user's row so both refreshes are inside their transactions, past the token lookup, when they meet.
        try (Connection holder = connect()) {
            holder.setAutoCommit(false);
            try (PreparedStatement lock = holder.prepareStatement("select id from t_users where id = ? for update")) {
                lock.setObject(1, session.userId());
                lock.executeQuery().close();
            }
            a = first.submit(() -> authService.refreshAccessToken(session.refreshToken(), META));
            b = second.submit(() -> authService.refreshAccessToken(session.refreshToken(), META));
            awaitLockWaiters(2);
            holder.commit();
        }

        List<AuthResponse> results = List.of(a.get(20, TimeUnit.SECONDS), b.get(20, TimeUnit.SECONDS));

        assertThat(results).filteredOn(r -> r.getAccessToken() != null).hasSize(1);
        assertThat(results).filteredOn(r -> r.getAccessToken() == null && r.getRefreshToken() == null).hasSize(1);
        assertThat(rowsOf(session.userId())).containsExactly("ACCESS false", "REFRESH false", "REFRESH true");
    }

    @Test
    void aLogoutRacingARefreshLeavesNoSession() throws Exception {
        Session session = login();
        CountDownLatch rotated = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // Pause the refresh right after it marked the presented token rotated, before it writes the successor.
        doAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("race-first")) {
                rotated.countDown();
                release.await(20, TimeUnit.SECONDS);
            }
            return invocation.callRealMethod();
        }).when(jwtUtil).generateToken(any());

        Future<AuthResponse> refresh = first.submit(() -> authService.refreshAccessToken(session.refreshToken(), META));
        assertThat(rotated.await(10, TimeUnit.SECONDS)).isTrue();
        Future<?> logout = second.submit(() -> logout(session));
        awaitLockWaiters(1);
        release.countDown();

        refresh.get(20, TimeUnit.SECONDS);
        logout.get(20, TimeUnit.SECONDS);
        assertThat(rowsOf(session.userId())).isEmpty();
    }

    @Test
    void aGoogleLoginRacingARefreshLeavesOnlyItsOwnSession() throws Exception {
        Session session = login();
        String email = jdbc.queryForObject("select email from t_users where id = ?", String.class, session.userId());
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(ExchangeTokenResponse.builder()
                        .idToken(googleIdToken(email, "race-nonce")).build()));
        CountDownLatch rotated = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // Pause the refresh right after it marked the presented token rotated, before it writes the successor.
        doAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("race-first")) {
                rotated.countDown();
                release.await(20, TimeUnit.SECONDS);
            }
            return invocation.callRealMethod();
        }).when(jwtUtil).generateToken(any());

        Future<AuthResponse> refresh = first.submit(() -> authService.refreshAccessToken(session.refreshToken(), META));
        assertThat(rotated.await(10, TimeUnit.SECONDS)).isTrue();
        Future<AuthResponse> google = second.submit(
                () -> authService.authenticateGoogleUser("code", "verifier", "race-nonce", META));
        awaitLockWaiters(1);
        release.countDown();

        assertThat(refresh.get(20, TimeUnit.SECONDS).getRefreshToken()).isNotNull();
        AuthResponse signedIn = google.get(20, TimeUnit.SECONDS);
        // The login's tokens replace every earlier one, including the successor the refresh committed meanwhile.
        assertThat(jdbc.queryForList("select token from t_tokens where user_id = ?", String.class, session.userId()))
                .containsExactlyInAnyOrder(
                        TokenHasher.sha256Hex(signedIn.getAccessToken()),
                        TokenHasher.sha256Hex(signedIn.getRefreshToken()));
    }

    /** What Google's token endpoint returns for a verified account with this email. */
    private String googleIdToken(String email, String nonce) {
        return new PlainJWT(new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com")
                .audience(googleClientId)
                .subject("google-sub-" + UUID.randomUUID())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("nonce", nonce)
                .claim("email", email)
                .claim("email_verified", true)
                .build()).serialize();
    }

    /** A logout whose access token has expired: the refresh cookie names the session. */
    private void logout(Session session) {
        authService.logout(session.refreshToken());
    }
}
