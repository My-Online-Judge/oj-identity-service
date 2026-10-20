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
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.UserService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    @Autowired UserService userService;

    @MockitoSpyBean PasswordEncoder passwordEncoder;
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
        User user = seedUser();
        AuthResponse tokens = authService.authenticateWithPassword(user.getUsername(), PASSWORD, META);
        return new Session(user.getId(), tokens.getRefreshToken());
    }

    private User seedUser() {
        String username = "race_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode(PASSWORD))
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
    }

    /** Starts a login with the right password and pauses it right after BCrypt said so. */
    private Future<AuthResponse> loginPausedAfterThePasswordCheck(User user, CountDownLatch checked,
                                                                 CountDownLatch release) throws Exception {
        doAnswer(invocation -> {
            Object matched = invocation.callRealMethod();
            if (Thread.currentThread().getName().equals("race-first")) {
                checked.countDown();
                release.await(20, TimeUnit.SECONDS);
            }
            return matched;
        }).when(passwordEncoder).matches(any(), any());
        Future<AuthResponse> login = first.submit(
                () -> authService.authenticateWithPassword(user.getUsername(), PASSWORD, META));
        assertThat(checked.await(10, TimeUnit.SECONDS)).isTrue();
        return login;
    }

    private void assertTheLoginFailed(Future<AuthResponse> login) {
        // Answered like any wrong password, and nothing written.
        assertThatThrownBy(() -> login.get(20, TimeUnit.SECONDS))
                .hasCauseInstanceOf(AppException.class)
                .satisfies(e -> assertThat(((AppException) e.getCause()).getErrorCode())
                        .isEqualTo(ErrorCode.USER_NOT_EXISTED));
    }

    @Test
    void aLoginRacingAPasswordChangeMintsNothing() throws Exception {
        User user = seedUser();
        CountDownLatch checked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<AuthResponse> login = loginPausedAfterThePasswordCheck(user, checked, release);

        second.submit(() -> {
            // Signed in: the caller is its access token's uid.
            Jwt jwt = Jwt.withTokenValue("access.token").header("alg", "RS256").subject(user.getUsername())
                    .claim("uid", user.getId().toString()).build();
            SecurityContextHolder.getContext().setAuthentication(
                    new JwtAuthenticationToken(jwt, List.of(), user.getUsername()));
            try {
                userService.changeOwnPassword(PASSWORD, "Changed123");
            } finally {
                SecurityContextHolder.clearContext();
            }
            return null;
        }).get(20, TimeUnit.SECONDS);
        release.countDown();

        assertTheLoginFailed(login);
        assertThat(rowsOf(user.getId())).isEmpty();
    }

    @Test
    void aLoginRacingAPasswordResetMintsNothing() throws Exception {
        User user = seedUser();
        CountDownLatch checked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<AuthResponse> login = loginPausedAfterThePasswordCheck(user, checked, release);

        second.submit(() -> userService.resetPassword(user.getId(), "Reset1234")).get(20, TimeUnit.SECONDS);
        release.countDown();

        assertTheLoginFailed(login);
        assertThat(rowsOf(user.getId())).isEmpty();
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
                .thenReturn(ResponseEntity.ok(new ExchangeTokenResponse(null, null, null, null, null,
                        googleIdToken(email, "race-nonce"))));
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

    @Test
    void twoFirstGoogleSignInsOfOneNewAccount_bothSignInToTheOneAccount() throws Exception {
        String email = "new_" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        // One Google account (one sub), signing in for the first time from two tabs at once.
        String idToken = googleIdToken(email, "race-nonce");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(new ExchangeTokenResponse(null, null, null, null, null, idToken)));
        CountDownLatch inserted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // Pause the first sign-in after it inserted the new account, before it commits.
        doAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("race-first")) {
                inserted.countDown();
                release.await(20, TimeUnit.SECONDS);
            }
            return invocation.callRealMethod();
        }).when(jwtUtil).generateToken(any());

        Future<AuthResponse> a = first.submit(
                () -> authService.authenticateGoogleUser("code", "verifier", "race-nonce", META));
        assertThat(inserted.await(10, TimeUnit.SECONDS)).isTrue();
        // The second found no account either; its insert waits on the first's uncommitted username.
        Future<AuthResponse> b = second.submit(
                () -> authService.authenticateGoogleUser("code", "verifier", "race-nonce", META));
        awaitLockWaiters(1);
        release.countDown();

        assertThat(a.get(20, TimeUnit.SECONDS).getAccessToken()).isNotNull();
        // The loser signs in to the account the winner created, instead of being told the username is taken.
        AuthResponse loser = b.get(20, TimeUnit.SECONDS);
        assertThat(loser.getAccessToken()).isNotNull();
        UUID account = jdbc.queryForObject("select id from t_users where lower(email) = lower(?)", UUID.class, email);
        assertThat(jdbc.queryForList("select token from t_tokens where user_id = ?", String.class, account))
                .containsExactlyInAnyOrder(
                        TokenHasher.sha256Hex(loser.getAccessToken()), TokenHasher.sha256Hex(loser.getRefreshToken()));
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
                // A Workspace account: Google is authoritative for its address, so an existing account may be linked.
                .claim("hd", "example.com")
                .build()).serialize();
    }

    /** Locks the user's row from a connection of the test's own, as a slow writer would hold it. */
    private Connection holdUserRow(UUID userId) throws Exception {
        Connection holder = connect();
        holder.setAutoCommit(false);
        try (PreparedStatement lock = holder.prepareStatement("select id from t_users where id = ? for update")) {
            lock.setObject(1, userId);
            lock.executeQuery().close();
        }
        return holder;
    }

    /** The call gives up on the user's row after the 5 s lock timeout with a clean 503, instead of waiting forever. */
    private void assertGivesUpWith503(Callable<?> call, UUID userId) throws Exception {
        assertGivesUpWith503(call, userId, Duration.ofMillis(4_500), Duration.ofSeconds(9));
    }

    private void assertGivesUpWith503(Callable<?> call, UUID userId, Duration atLeast, Duration atMost)
            throws Exception {
        try (Connection holder = holdUserRow(userId)) {
            long start = System.nanoTime();
            Future<?> result = first.submit(call);
            try {
                assertThatThrownBy(() -> result.get(atMost.toSeconds() + 1, TimeUnit.SECONDS))
                        .isInstanceOf(ExecutionException.class)
                        .cause()
                        .isInstanceOfSatisfying(AppException.class, e -> {
                            assertThat(e.getErrorCode()).isEqualTo(ErrorCode.ACCOUNT_BUSY);
                            assertThat(e.getErrorCode().getStatusCode().value()).isEqualTo(503);
                        });
                assertThat(Duration.ofNanos(System.nanoTime() - start)).isBetween(atLeast, atMost);
            } finally {
                holder.rollback();
            }
        }
    }

    @Test
    void aRefreshWaitingTooLongForTheUserRowAnswers503_andRotatesNothing() throws Exception {
        Session session = login();

        // The hardest caller: its dontRollbackOn would otherwise try to commit the failed transaction.
        assertGivesUpWith503(() -> authService.refreshAccessToken(session.refreshToken(), META), session.userId());

        assertThat(rowsOf(session.userId())).containsExactly("ACCESS false", "REFRESH false");
    }

    @Test
    void aLogoutWaitingTooLongForTheUserRowAnswers503() throws Exception {
        Session session = login();

        // Two waits: it tries once more before giving up.
        assertGivesUpWith503(() -> {
            authService.logout(session.refreshToken());
            return null;
        }, session.userId(), Duration.ofMillis(9_500), Duration.ofSeconds(18));

        assertThat(rowsOf(session.userId())).containsExactly("ACCESS false", "REFRESH false");
    }

    /**
     * A logout whose first wait for the user row gives up (5 s) tries once more, in a fresh transaction: the row is free
     * by then, and every session ends. The browser's cookies are cleared whatever logout answers, so giving up at once
     * would leave every other session alive with nothing left to retry from.
     */
    @Test
    void aLogoutWhoseFirstWaitTimesOut_triesOnceMore_andEndsEverySession() throws Exception {
        Session session = login();
        Future<?> loggingOut;
        try (Connection holder = holdUserRow(session.userId())) {
            loggingOut = first.submit(() -> {
                logout(session);
                return null;
            });
            awaitLockWaiters(1);
            // Longer than one lock timeout, shorter than two: the first wait has given up, the second is waiting.
            Thread.sleep(6_500);
            holder.rollback();
        }

        loggingOut.get(10, TimeUnit.SECONDS);
        assertThat(rowsOf(session.userId())).isEmpty();
    }

    @Test
    void aPasswordResetWaitingTooLongForTheUserRowAnswers503_andChangesNothing() throws Exception {
        Session session = login();
        String hash = passwordOf(session.userId());

        // The flushed UPDATE of the password is the statement that meets the held row, so the lock timeout must
        // already be in force when it runs, not only for the SELECT … FOR UPDATE after it.
        assertGivesUpWith503(() -> {
            userService.resetPassword(session.userId(), "Reset1234");
            return null;
        }, session.userId());

        assertThat(passwordOf(session.userId())).isEqualTo(hash);
        assertThat(rowsOf(session.userId())).containsExactly("ACCESS false", "REFRESH false");
    }

    private String passwordOf(UUID userId) {
        return jdbc.queryForObject("select password from t_users where id = ?", String.class, userId);
    }

    /** A logout whose access token has expired: the refresh cookie names the session. */
    private void logout(Session session) {
        authService.logout(session.refreshToken());
    }
}
