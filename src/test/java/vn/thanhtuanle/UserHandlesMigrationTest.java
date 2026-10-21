package vn.thanhtuanle;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.CoreMigrationType;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.user.HandleAllocator;
import vn.thanhtuanle.user.UserHandles;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V8: every live account whose username is an email address (a Google sign-up from before handles) gets the handle the
 * sign-up would give it now, from its display name (Q1), oldest account first. Soft-deleted rows stay as they are.
 */
@Testcontainers(disabledWithoutDocker = true)
class UserHandlesMigrationTest {

    private static final int ACTIVE = 1;
    private static final int DELETED = 2;
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void emailUsernamesGetHandles() throws SQLException {
        cleanAndMigrate("7");
        UUID alice = insertUser("alice", "alice@example.com", "Alice", ACTIVE, 1);
        UUID aliceGmail = insertUser("alice@gmail.com", "alice@gmail.com", "Alice", ACTIVE, 2);
        UUID aliceWork = insertUser("Alice@work.org", "Alice@work.org", "Alice", ACTIVE, 3);
        UUID bob = insertUser("bob.smith@gmail.com", "bob.smith@gmail.com", "Bob Smith", ACTIVE, 4);
        UUID carol = insertUser("carol@gmail.com", "carol@gmail.com", "Carol", DELETED, 5);
        UUID dave = insertUser("dave", "dave@example.com", "Dave", ACTIVE, 6);

        flyway("latest").migrate();

        assertThat(username(aliceGmail)).isEqualTo("alice_2");
        assertThat(username(aliceWork)).isEqualTo("alice_3");
        assertThat(username(bob)).isEqualTo("bob_smith");
        assertThat(username(carol)).isEqualTo("carol@gmail.com");
        assertThat(username(alice)).isEqualTo("alice");
        assertThat(username(dave)).isEqualTo("dave");
        assertThat(updatedByV8()).containsExactlyInAnyOrder(aliceGmail, aliceWork, bob);
        // Only the username changes: the email stays private and where it was.
        assertThat(email(bob)).isEqualTo("bob.smith@gmail.com");
    }

    /** Q1: the handle comes from the display name, never from the address. */
    @Test
    void theHandleComesFromTheDisplayNameNotTheEmail() throws SQLException {
        cleanAndMigrate("7");
        UUID tuan = insertUser("tl.2001@gmail.com", "tl.2001@gmail.com", "Lê Thanh Tuấn", ACTIVE, 1);
        UUID nameless = insertUser("nobody@gmail.com", "nobody@gmail.com", null, ACTIVE, 2);

        flyway("latest").migrate();

        assertThat(username(tuan)).isEqualTo("le_thanh_tuan");
        assertThat(username(nameless)).matches("user[0-9a-f]{6}");
    }

    @Test
    void theOldestAccountGetsTheBareBase() throws SQLException {
        cleanAndMigrate("7");
        UUID second = insertUser("x@a.org", "x@a.org", "Xu Ân", ACTIVE, 2);
        UUID first = insertUser("x@b.org", "x@b.org", "Xu An", ACTIVE, 1);

        flyway("latest").migrate();

        assertThat(username(first)).isEqualTo("xu_an");
        assertThat(username(second)).isEqualTo("xu_an_2");
    }

    /** The backfill picks, row by row and oldest first, what the sign-up's allocator would pick. */
    @Test
    void backfillMatchesTheAllocator() throws SQLException {
        cleanAndMigrate("7");
        Map<UUID, String> names = new LinkedHashMap<>();
        insertUser("nguyen", "nguyen@example.com", "Nguyen", ACTIVE, 0);
        String[] corpus = {"Nguyễn", "nguyen", "Trần Thị Bích", "TRAN thi bich", "Đức", "Đặng Đức", "A", "ab",
                "a_b__c", "Zoë Smith-Jones", "Nguyễn Văn A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
        for (int i = 0; i < corpus.length; i++) {
            names.put(insertUser("u" + i + "@gmail.com", "u" + i + "@gmail.com", corpus[i], ACTIVE, i + 1), corpus[i]);
        }

        flyway("latest").migrate();

        Set<String> taken = new HashSet<>(Set.of("nguyen"));
        for (Map.Entry<UUID, String> row : names.entrySet()) {
            String expected = UserHandles.allocate(HandleAllocator.sourceOf(null, row.getValue()),
                    handle -> taken.contains(handle.toLowerCase()), new Random());
            taken.add(expected);
            assertThat(username(row.getKey())).as(row.getValue()).isEqualTo(expected);
        }
    }

    @Test
    void noEmailUsernamesNoChange() throws SQLException {
        cleanAndMigrate("latest");

        assertThat(updatedByV8()).isEmpty();
    }

    @Test
    void v8IsAJavaMigrationAtVersion8() {
        cleanAndMigrate("latest");

        MigrationInfo current = flyway("latest").info().current();
        assertThat(current.getVersion().getVersion()).isEqualTo("8");
        assertThat(current.getType()).isEqualTo(CoreMigrationType.JDBC);
    }

    private static UUID insertUser(String username, String email, String name, int status, int minutesAfterT0)
            throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection c = connection(); PreparedStatement ps = c.prepareStatement("""
                INSERT INTO t_users (id, created_at, updated_at, username, email, name, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)""")) {
            Timestamp createdAt = Timestamp.from(T0.plusSeconds(60L * minutesAfterT0));
            ps.setObject(1, id);
            ps.setTimestamp(2, createdAt);
            ps.setTimestamp(3, createdAt);
            ps.setString(4, username);
            ps.setString(5, email);
            ps.setString(6, name);
            ps.setInt(7, status);
            ps.executeUpdate();
        }
        return id;
    }

    private static String username(UUID id) throws SQLException {
        return column("username", id);
    }

    private static String email(UUID id) throws SQLException {
        return column("email", id);
    }

    private static String column(String column, UUID id) throws SQLException {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement("SELECT " + column + " FROM t_users WHERE id = ?")) {
            ps.setObject(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                assertThat(rs.next()).isTrue();
                return rs.getString(1);
            }
        }
    }

    private static Set<UUID> updatedByV8() throws SQLException {
        Set<UUID> ids = new HashSet<>();
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement("SELECT id FROM t_users WHERE updated_by = 'V8'");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                ids.add(rs.getObject(1, UUID.class));
            }
        }
        return ids;
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
