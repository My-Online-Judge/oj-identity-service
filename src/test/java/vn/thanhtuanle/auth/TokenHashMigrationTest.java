package vn.thanhtuanle.auth;

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

/**
 * V5 hashes every stored token in place, so a session that was live before the deploy keeps working: the app now looks
 * a presented token up by its SHA-256 hex, and that is exactly what the row holds after the migration. The hash the
 * database computes must equal the one {@link TokenHasher} computes, or every existing session would end.
 */
@Testcontainers(disabledWithoutDocker = true)
class TokenHashMigrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @Test
    void existingTokensAreHashedInPlace() throws SQLException {
        flyway("4").migrate();
        UUID userId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        try (Connection c = connection()) {
            try (PreparedStatement ps = c.prepareStatement("""
                    INSERT INTO t_users (id, created_at, updated_at, username, email, status)
                    VALUES (?, now(), now(), 'alice', 'alice@example.com', 1)""")) {
                ps.setObject(1, userId);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement("""
                    INSERT INTO t_tokens (id, created_at, updated_at, expired, revoked, token, token_type, user_id)
                    VALUES (?, now(), now(), false, false, 'header.payload.sig', 'REFRESH', ?)""")) {
                ps.setObject(1, tokenId);
                ps.setObject(2, userId);
                ps.executeUpdate();
            }
        }

        flyway("latest").migrate();

        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement("SELECT token, rotated_at FROM t_tokens WHERE id = ?")) {
            ps.setObject(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getString("token")).isEqualTo(TokenHasher.sha256Hex("header.payload.sig"));
                assertThat(rs.getTimestamp("rotated_at")).isNull();
            }
        }
    }

    private static Flyway flyway(String target) {
        return Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").target(target).load();
    }

    private static Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
