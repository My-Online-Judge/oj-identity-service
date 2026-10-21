package vn.thanhtuanle.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.auth.AuthService;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.auth.TokenBlocklist;
import vn.thanhtuanle.auth.TokenHasher;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.repository.TokenRepository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The user's row lock on real Postgres: the lock timeout is set for each call, and a logout gives up within two short
 * waits, well before the portal's 10 s request timeout.
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class UserRowLockOnPostgresTest {

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

    @Autowired UserRepository userRepository;
    @Autowired TokenRepository tokenRepository;
    @Autowired AuthService authService;
    @Autowired TransactionTemplate transactionTemplate;
    @Autowired JdbcTemplate jdbc;

    /** No Redis in the test profile: the after-commit revocation and the blocklist are not what this tests. */
    @MockitoBean SessionRevoker sessionRevoker;
    @MockitoBean TokenBlocklist tokenBlocklist;

    private final ExecutorService holderThread = Executors.newSingleThreadExecutor(r -> new Thread(r, "row-holder"));

    @AfterEach
    void stopThreads() {
        holderThread.shutdownNow();
    }

    private User seedUser() {
        String username = "lock_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(User.builder().username(username).name(username)
                .email(username + "@example.com").password("{noop}unused").status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>()).build());
    }

    private Connection connect() throws Exception {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @Test
    void theTimeoutIsSetPerCall() {
        UUID id = seedUser().getId();

        String[] seen = transactionTemplate.execute(status -> {
            userRepository.lockById(id, Duration.ofSeconds(3));
            String shortWait = jdbc.queryForObject("show lock_timeout", String.class);
            userRepository.lockById(id);
            String defaultWait = jdbc.queryForObject("show lock_timeout", String.class);
            return new String[] {shortWait, defaultWait};
        });

        assertThat(seen).containsExactly("3s", "5s");
    }

    @Test
    void logoutGivesUpWithinTwoShortWaits() throws Exception {
        User user = seedUser();
        String refreshToken = "refresh-" + UUID.randomUUID();
        tokenRepository.save(Token.builder().token(TokenHasher.sha256Hex(refreshToken)).tokenType(TokenType.REFRESH)
                .user(user).build());

        // Another transaction holds the user's row for 8 s: longer than two 3 s waits, shorter than two 5 s waits.
        CountDownLatch held = new CountDownLatch(1);
        Future<?> holder = holderThread.submit(() -> {
            try (Connection connection = connect()) {
                connection.setAutoCommit(false);
                try (PreparedStatement lock = connection.prepareStatement(
                        "select id from t_users where id = ? for update")) {
                    lock.setObject(1, user.getId());
                    lock.executeQuery().close();
                }
                held.countDown();
                Thread.sleep(8_000);
                connection.rollback();
            }
            return null;
        });
        assertThat(held.await(10, TimeUnit.SECONDS)).isTrue();

        long start = System.nanoTime();
        assertThatThrownBy(() -> authService.logout(refreshToken)).isInstanceOf(UserLockTimeoutException.class);
        Duration took = Duration.ofNanos(System.nanoTime() - start);

        assertThat(took).isBetween(Duration.ofMillis(5_500), Duration.ofMillis(7_500));
        holder.get(10, TimeUnit.SECONDS);
        assertThat(jdbc.queryForObject("select count(*) from t_tokens where user_id = ?", Integer.class, user.getId()))
                .isEqualTo(1);
    }
}
