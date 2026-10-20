package vn.thanhtuanle;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * V6: one live account (status not 2) per username and per email, case-insensitively, and per Google id. A database
 * that already breaks this refuses to migrate and names the duplicates (judge-deployment/migrations/sp12-dupes.sh lists
 * them with their ids). V6 also indexes t_tokens by user, for the per-user deletes.
 */
@Testcontainers(disabledWithoutDocker = true)
class UniqueUserIdentityMigrationTest {

    private static final int ACTIVE = 1;
    private static final int DISABLED = 0;
    private static final int DELETED = 2;

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void duplicatesBlockTheMigrationWithTheirNames() throws SQLException {
        cleanAndMigrate("5");
        insertUser("Alice", "alice.one@example.com", null, ACTIVE);
        insertUser("alice", "alice.two@example.com", null, ACTIVE);

        assertThatThrownBy(() -> flyway("latest").migrate())
                .hasMessageContaining("V6: resolve duplicate users first")
                .hasMessageContaining("username alice");
        assertThat(indexExists("ux_users_username_lower")).isFalse();
    }

    @Test
    void duplicateEmailsAndGoogleIdsBlockItToo() throws SQLException {
        cleanAndMigrate("5");
        insertUser("bob", "Bob@X.io", "g-1", ACTIVE);
        insertUser("bobby", "bob@x.io", "g-1", DISABLED);

        assertThatThrownBy(() -> flyway("latest").migrate())
                .hasMessageContaining("email bob@x.io")
                .hasMessageContaining("google_id g-1");
    }

    @Test
    void deletedDuplicatesDoNotBlock() throws SQLException {
        cleanAndMigrate("5");
        insertUser("carol", "carol@example.com", "g-carol", ACTIVE);
        insertUser("Carol", "CAROL@example.com", "g-carol", DELETED);

        assertThatCode(() -> flyway("latest").migrate()).doesNotThrowAnyException();
        assertThat(indexExists("ux_users_username_lower")).isTrue();
    }

    @Test
    void indexesRejectCaseVariants() throws SQLException {
        cleanAndMigrate("latest");
        insertUser("bob", "bob@example.com", "g-bob", ACTIVE);

        assertViolates("ux_users_username_lower", () -> insertUser("BOB", "other@example.com", null, ACTIVE));
        assertViolates("ux_users_email_lower", () -> insertUser("bob2", "BOB@Example.com", null, DISABLED));
        assertViolates("ux_users_google_id", () -> insertUser("bob3", "bob3@example.com", "g-bob", ACTIVE));

        // A soft-deleted account keeps its name, email and Google id out of the way of live ones.
        assertThatCode(() -> insertUser("BOB", "BOB@example.com", "g-bob", DELETED)).doesNotThrowAnyException();
        // Accounts without a Google id are not one Google id.
        assertThatCode(() -> {
            insertUser("dave", "dave@example.com", null, ACTIVE);
            insertUser("erin", "erin@example.com", null, ACTIVE);
        }).doesNotThrowAnyException();
    }

    @Test
    void tokensAreIndexedByUser() throws SQLException {
        cleanAndMigrate("latest");

        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'ix_tokens_user_id'");
             ResultSet rs = ps.executeQuery()) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString(1)).contains("ON public.t_tokens").contains("(user_id)");
        }
    }

    private interface SqlAction {
        void run() throws SQLException;
    }

    private static void assertViolates(String index, SqlAction insert) {
        assertThatThrownBy(insert::run)
                .isInstanceOfSatisfying(SQLException.class, e -> assertThat(e.getSQLState()).isEqualTo("23505"))
                .hasMessageContaining(index);
    }

    private static void insertUser(String username, String email, String googleId, int status) throws SQLException {
        try (Connection c = connection(); PreparedStatement ps = c.prepareStatement("""
                INSERT INTO t_users (id, created_at, updated_at, username, email, google_id, status)
                VALUES (?, now(), now(), ?, ?, ?, ?)""")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, username);
            ps.setString(3, email);
            ps.setString(4, googleId);
            ps.setInt(5, status);
            ps.executeUpdate();
        }
    }

    private static boolean indexExists(String name) throws SQLException {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement("SELECT 1 FROM pg_indexes WHERE indexname = ?")) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static void cleanAndMigrate(String target) {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false).locations("classpath:db/migration").load().clean();
        flyway(target).migrate();
    }

    private static Flyway flyway(String target) {
        return Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").target(target).load();
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
