package vn.thanhtuanle;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V7 adds contest:create, contest:update and contest:delete and grants them to ADMIN and SYS_ROOT, matched by role name
 * because the live role ids differ from the seed's. The statements are safe to replay.
 */
@Testcontainers(disabledWithoutDocker = true)
class ContestPermissionsMigrationTest {

    private static final String[] CONTEST = {"contest:create", "contest:delete", "contest:update"};

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void adminAndRootGetTheContestPermissions() throws SQLException {
        cleanAndMigrate();

        assertThat(contestPermissionsOf("ADMIN")).containsExactlyInAnyOrder(CONTEST);
        assertThat(contestPermissionsOf("SYS_ROOT")).containsExactlyInAnyOrder(CONTEST);
        assertThat(contestPermissionsOf("USER")).isEmpty();
    }

    @Test
    void replayingTheStatementsChangesNothing() throws SQLException, IOException {
        cleanAndMigrate();
        int permissions = count("SELECT count(*) FROM t_permissions");
        int grants = count("SELECT count(*) FROM t_roles_permissions");

        try (Connection c = connection(); InputStream in = getClass().getResourceAsStream(
                "/db/migration/V7__contest_permissions.sql")) {
            c.createStatement().execute(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }

        assertThat(count("SELECT count(*) FROM t_permissions")).isEqualTo(permissions);
        assertThat(count("SELECT count(*) FROM t_roles_permissions")).isEqualTo(grants);
        assertThat(count("SELECT count(*) FROM t_permissions WHERE name LIKE 'contest:%'")).isEqualTo(3);
    }

    private static void cleanAndMigrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false).locations("classpath:db/migration").load().clean();
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static int count(String sql) throws SQLException {
        try (Connection c = connection(); ResultSet rs = c.createStatement().executeQuery(sql)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private static List<String> contestPermissionsOf(String role) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection c = connection(); ResultSet rs = c.createStatement().executeQuery("""
                SELECT p.name FROM t_roles r
                JOIN t_roles_permissions rp ON rp.role_id = r.id
                JOIN t_permissions p ON p.id = rp.permission_id
                WHERE r.name = '%s' AND p.name LIKE 'contest:%%'""".formatted(role))) {
            while (rs.next()) {
                names.add(rs.getString(1));
            }
        }
        return names;
    }
}
