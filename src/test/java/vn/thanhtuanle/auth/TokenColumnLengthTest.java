package vn.thanhtuanle.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Reproduces the live login outage from task-4b: t_tokens.token is varchar(255), but an RS256
 * access token (RSA-2048 signature -> ~342 base64 chars for the signature segment alone, plus
 * the kid header) is well over that. H2, which the rest of the suite runs on, does not enforce
 * varchar column length under ddl-auto=update, so this must run against real Postgres via
 * Testcontainers to catch it. See .superpowers/sdd/task-4b-brief.md.
 */
@Testcontainers
class TokenColumnLengthTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    /** Runs the real Flyway migration chain (V1..latest) against the container, same as prod. */
    private static void migrate() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .baselineOnMigrate(false)
                .load()
                .migrate();
    }

    /**
     * A real RS256 access token, not a magic-number stand-in: a freshly generated 2048-bit
     * RSA keypair signs it, so its length genuinely reflects what JwtUtil produces in prod.
     */
    private static String realRs256Token() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        return Jwts.builder()
                .setSubject("token-length-probe")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(pair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    private static void insertToken(Connection conn, UUID id, String token) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO t_tokens (id, created_at, updated_at, expired, revoked, token, token_type) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            ps.setObject(1, id);
            ps.setTimestamp(2, Timestamp.from(Instant.now()));
            ps.setTimestamp(3, Timestamp.from(Instant.now()));
            ps.setBoolean(4, false);
            ps.setBoolean(5, false);
            ps.setString(6, token);
            ps.setString(7, "ACCESS");
            ps.executeUpdate();
        }
    }

    @Test
    void realRs256Token_roundTrips_andUniqueConstraintStillHolds() throws Exception {
        migrate();

        String token = realRs256Token();
        // Sanity check that this is genuinely the scenario that broke prod, not a shorter stand-in.
        assertThat(token.length()).isGreaterThan(255);

        UUID id = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {

            insertToken(conn, id, token);

            try (PreparedStatement ps = conn.prepareStatement("SELECT token FROM t_tokens WHERE id = ?")) {
                ps.setObject(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    assertThat(rs.next()).isTrue();
                    assertThat(rs.getString("token")).isEqualTo(token); // byte-identical round-trip
                }
            }

            // UNIQUE constraint (ukdjdnp60wf0lq8erni3suse1np on t_tokens.token) must survive the
            // ALTER TYPE text and still reject a duplicate token value.
            UUID dupeId = UUID.randomUUID();
            assertThatThrownBy(() -> insertToken(conn, dupeId, token))
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("duplicate key value violates unique constraint");
        }
    }
}
