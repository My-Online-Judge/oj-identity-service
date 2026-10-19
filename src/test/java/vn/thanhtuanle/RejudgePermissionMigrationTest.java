package vn.thanhtuanle;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V4 adds submission:rejudge and grants it to ADMIN and SYS_ROOT, matched by role name because the live role ids differ
 * from the seed's. Re-running over a database that already has the permission must not duplicate anything.
 */
@Testcontainers(disabledWithoutDocker = true)
class RejudgePermissionMigrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void adminAndRootGetRejudgeAndUsersDoNot() throws SQLException {
        cleanAndMigrate("3");
        flyway("latest").migrate();

        assertThat(permissionsOf("ADMIN")).contains("submission:rejudge");
        assertThat(permissionsOf("SYS_ROOT")).contains("submission:rejudge");
        assertThat(permissionsOf("USER")).doesNotContain("submission:rejudge");
    }

    @Test
    void aDatabaseThatAlreadyHasItGetsNoDuplicates() throws SQLException {
        cleanAndMigrate("3");
        try (Connection c = connection()) {
            c.createStatement().executeUpdate("""
                    INSERT INTO t_permissions (id, created_at, created_by, updated_at, updated_by, description, name)
                    VALUES ('c1000000-0000-0000-0000-000000000001', now(), 'HAND', now(), 'HAND',
                            'by hand', 'submission:rejudge')""");
            c.createStatement().executeUpdate("""
                    INSERT INTO t_roles_permissions (role_id, permission_id)
                    SELECT r.id, 'c1000000-0000-0000-0000-000000000001' FROM t_roles r
                    WHERE r.name IN ('ADMIN', 'SYS_ROOT')""");
        }

        flyway("latest").migrate();

        assertThat(count("SELECT count(*) FROM t_permissions WHERE name = 'submission:rejudge'")).isEqualTo(1);
        assertThat(count("""
                SELECT count(*) FROM t_roles_permissions rp JOIN t_permissions p ON p.id = rp.permission_id
                WHERE p.name = 'submission:rejudge'""")).isEqualTo(2);
        assertThat(permissionsOf("ADMIN")).containsOnlyOnce("submission:rejudge");
        assertThat(permissionsOf("SYS_ROOT")).containsOnlyOnce("submission:rejudge");
    }

    private static void cleanAndMigrate(String target) {
        Flyway clean = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .cleanDisabled(false).locations("classpath:db/migration").load();
        clean.clean();
        flyway(target).migrate();
    }

    private static Flyway flyway(String target) {
        return Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").target(target).load();
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

    private static List<String> permissionsOf(String role) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection c = connection(); ResultSet rs = c.createStatement().executeQuery("""
                SELECT p.name FROM t_roles r
                JOIN t_roles_permissions rp ON rp.role_id = r.id
                JOIN t_permissions p ON p.id = rp.permission_id
                WHERE r.name = '%s'""".formatted(role))) {
            while (rs.next()) {
                names.add(rs.getString(1));
            }
        }
        return names;
    }
}
