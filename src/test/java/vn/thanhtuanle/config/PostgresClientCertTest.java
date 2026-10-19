package vn.thanhtuanle.config;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Postgres started the way docker-compose.yml starts the three databases (ssl=on, the CA file, the pg-hba rules)
 * admits a client only over TLS and only with a certificate signed by the CA. The test-only fixtures are in
 * src/test/resources/tls.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresClientCertTest {

    private static final List<String> FIXTURES = List.of(
            "ca.crt", "server.crt", "server.key", "api-gateway.crt", "api-gateway.key", "pg_hba.conf");
    private static final List<String> CLIENT_FILES = List.of(
            "ca.crt", "api-gateway.crt", "api-gateway.key", "rogue-client.crt", "rogue-client.key");

    static GenericContainer<?> postgres;
    static Path clientDir;

    @BeforeAll
    static void startPostgres() throws Exception {
        // pgjdbc refuses a client key that is readable by others, and git does not keep file modes.
        clientDir = Files.createTempDirectory("pg-client");
        for (String f : CLIENT_FILES) {
            Path target = clientDir.resolve(f);
            try (var in = PostgresClientCertTest.class.getResourceAsStream("/tls/" + f)) {
                if (in == null) {
                    throw new IllegalStateException("test fixture missing from the classpath: /tls/" + f
                            + " (regenerate with judge-deployment/pki/pki.sh fixtures)");
                }
                Files.copy(in, target);
            }
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString(f.endsWith(".key") ? "rw-------" : "rw-r--r--"));
        }

        // The server runs as uid 999 and insists on owning a 0600 key, so the container installs the fixtures and
        // then hands over to the image entrypoint (same flags as docker-compose.yml).
        postgres = new GenericContainer<>("postgres:16")
                .withEnv("POSTGRES_PASSWORD", "secret")
                .withExposedPorts(5432)
                .withCommand("sh", "-c", "install -d -o postgres -m 700 /etc/oj/tls"
                        + " && install -o postgres -m 600 /tmp/fixtures/server.key /etc/oj/tls/tls.key"
                        + " && install -o postgres -m 644 /tmp/fixtures/server.crt /etc/oj/tls/tls.crt"
                        + " && install -o postgres -m 644 /tmp/fixtures/ca.crt /etc/oj/tls/ca.crt"
                        + " && install -m 644 /tmp/fixtures/pg_hba.conf /etc/oj/pg_hba.conf"
                        + " && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/etc/oj/tls/tls.crt"
                        + " -c ssl_key_file=/etc/oj/tls/tls.key -c ssl_ca_file=/etc/oj/tls/ca.crt"
                        + " -c hba_file=/etc/oj/pg_hba.conf")
                // The two "ready" lines are the init server and the final one; a JDBC wait would be refused by pg-hba.
                .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\n", 2));
        for (String f : FIXTURES) {
            postgres.withCopyFileToContainer(MountableFile.forClasspathResource("tls/" + f), "/tmp/fixtures/" + f);
        }
        postgres.start();
    }

    @AfterAll
    static void stop() {
        if (postgres != null) {
            postgres.stop();
        }
        if (clientDir != null) {
            try (var files = Files.walk(clientDir)) {
                files.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            } catch (java.io.IOException ignored) {
                // a leftover temp directory is harmless
            }
        }
    }

    private static String url(String params) {
        return "jdbc:postgresql://localhost:" + postgres.getMappedPort(5432) + "/postgres?" + params;
    }

    private static String ca() {
        return "sslrootcert=" + clientDir.resolve("ca.crt");
    }

    @Test
    void connectsWithClientCert() throws Exception {
        String params = "sslmode=verify-full&" + ca()
                + "&sslcert=" + clientDir.resolve("api-gateway.crt")
                + "&sslkey=" + clientDir.resolve("api-gateway.key");
        try (Connection c = DriverManager.getConnection(url(params), "postgres", "secret");
             Statement s = c.createStatement();
             ResultSet rs = s.executeQuery("select 1")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getInt(1)).isEqualTo(1);
        }
    }

    @Test
    void refusedWithoutClientCert() {
        assertThatThrownBy(() -> DriverManager.getConnection(url("sslmode=verify-full&" + ca()), "postgres", "secret").close())
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("certificate");
    }

    @Test
    void refusedWithClientCertFromAnotherCa() {
        String params = "sslmode=verify-full&" + ca()
                + "&sslcert=" + clientDir.resolve("rogue-client.crt")
                + "&sslkey=" + clientDir.resolve("rogue-client.key");
        assertThatThrownBy(() -> DriverManager.getConnection(url(params), "postgres", "secret").close())
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("certificate");
    }

    @Test
    void refusedPlaintext() {
        assertThatThrownBy(() -> DriverManager.getConnection(url("sslmode=disable"), "postgres", "secret").close())
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("no pg_hba.conf entry");
    }
}
