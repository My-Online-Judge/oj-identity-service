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
 * Live identity-db had judgeserver:read and permission:read granted to the USER role (2026-07-18, while the Roles page
 * was being built), so every ordinary user could open /admin. V3 revokes them. The test rebuilds that state on V2,
 * then migrates on, as Flyway does on the live database.
 */
@Testcontainers(disabledWithoutDocker = true)
class UserRoleAdminPermissionsMigrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void theUserRoleLosesTheAdminPermissionsItWasGranted() throws SQLException {
        flyway("2").migrate();
        try (Connection c = connection()) {
            c.createStatement().executeUpdate("""
                    INSERT INTO t_roles_permissions (role_id, permission_id)
                    SELECT r.id, p.id FROM t_roles r, t_permissions p
                    WHERE r.name = 'USER' AND p.name IN ('judgeserver:read', 'permission:read')""");
        }
        assertThat(userPermissions()).containsExactlyInAnyOrder("judgeserver:read", "permission:read");

        flyway("latest").migrate();

        assertThat(userPermissions()).isEmpty();
    }

    private static Flyway flyway(String target) {
        return Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").target(target).load();
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static List<String> userPermissions() throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection c = connection(); ResultSet rs = c.createStatement().executeQuery("""
                SELECT p.name FROM t_roles r
                JOIN t_roles_permissions rp ON rp.role_id = r.id
                JOIN t_permissions p ON p.id = rp.permission_id
                WHERE r.name = 'USER'""")) {
            while (rs.next()) {
                names.add(rs.getString(1));
            }
        }
        return names;
    }
}
