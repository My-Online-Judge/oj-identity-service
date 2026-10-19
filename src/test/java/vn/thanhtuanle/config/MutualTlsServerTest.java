package vn.thanhtuanle.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Under the tls profile both ports require a client certificate signed by the CA, and the API port answers only the
 * CNs in {@code oj.tls.allowed-clients}: oj-common's PeerCertificateFilter runs before Spring Security, so an allowed
 * caller still meets the usual 401. The actuator port has no CN allowlist (Prometheus and the healthcheck present
 * their own certificates). Test-only fixtures: src/test/resources/tls.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "management.server.port=0",
        "oj.tls.allowed-clients=api-gateway",
        // Health is UP only with Redis, which a test run does not start.
        "management.health.redis.enabled=false"})
@ActiveProfiles({"test", "tls"})
class MutualTlsServerTest {

    /** Needs authentication: an allowed caller without a token gets 401. */
    private static final String API_PATH = "/api/v1/roles";

    private static Path tlsDir;

    @LocalServerPort
    private int apiPort;
    @LocalManagementPort
    private int managementPort;

    @DynamicPropertySource
    static void certificates(DynamicPropertyRegistry registry) throws IOException {
        tlsDir = Files.createTempDirectory("oj-tls");
        for (Map.Entry<String, String> f : Map.of("server.crt", "tls.crt", "server.key", "tls.key", "ca.crt", "ca.crt")
                .entrySet()) {
            try (InputStream in = MutualTlsServerTest.class.getResourceAsStream("/tls/" + f.getKey())) {
                if (in == null) {
                    throw new IllegalStateException("test fixture missing from the classpath: /tls/" + f.getKey()
                            + " (regenerate with judge-deployment/pki/pki.sh fixtures)");
                }
                Files.copy(in, tlsDir.resolve(f.getValue()));
            }
        }
        registry.add("OJ_TLS_DIR", tlsDir::toString);
    }

    @AfterAll
    static void deleteTlsDir() throws IOException {
        try (var files = Files.walk(tlsDir)) {
            files.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    void allowedClientReachesHealth() throws Exception {
        HttpClient client = clientPresenting("api-gateway");

        assertThat(get(client, managementPort, "/actuator/health").statusCode()).isEqualTo(200);
        assertThat(get(client, apiPort, API_PATH).statusCode()).isEqualTo(401);
    }

    @Test
    void probeCnGets403() throws Exception {
        HttpClient client = clientPresenting("tls-probe");

        HttpResponse<String> response = get(client, apiPort, API_PATH);
        assertThat(response.statusCode()).isEqualTo(403);
        JsonNode body = new ObjectMapper().readTree(response.body());
        assertThat(body.get("status").asInt()).isEqualTo(403);
        assertThat(body.get("message").asText()).isEqualTo("Client certificate not allowed");
        // The CN allowlist guards the API only.
        assertThat(get(client, managementPort, "/actuator/health").statusCode()).isEqualTo(200);
    }

    @Test
    void noClientCertFailsHandshake() throws Exception {
        HttpClient client = clientPresenting(null);

        assertRefused(catchThrowable(() -> get(client, apiPort, API_PATH)));
        assertRefused(catchThrowable(() -> get(client, managementPort, "/actuator/health")));
    }

    @Test
    void rogueCertFailsHandshake() throws Exception {
        AtomicBoolean presented = new AtomicBoolean();
        HttpClient client = clientPresenting("rogue-client", presented);

        assertRefused(catchThrowable(() -> get(client, apiPort, API_PATH)));
        assertThat(presented).as("the foreign-CA certificate was sent, not withheld").isTrue();
        presented.set(false);
        assertRefused(catchThrowable(() -> get(client, managementPort, "/actuator/health")));
        assertThat(presented).as("the foreign-CA certificate was sent, not withheld").isTrue();
    }

    /** TLS 1.3 reports a refused client certificate after the handshake, on the first read. */
    private static void assertRefused(Throwable thrown) {
        assertThat(thrown).as("the request must not get an HTTP answer").isNotNull();
        assertThat(thrown).isInstanceOfAny(SSLHandshakeException.class, SocketException.class);
    }

    private static HttpClient clientPresenting(String identity) throws GeneralSecurityException {
        return clientPresenting(identity, new AtomicBoolean());
    }

    /**
     * A client trusting the test CA and presenting the fixture {@code identity} (none when null); {@code presented}
     * turns true when a handshake sends it.
     */
    private static HttpClient clientPresenting(String identity, AtomicBoolean presented)
            throws GeneralSecurityException {
        PemSslStoreDetails keyStore = identity == null ? null
                : new PemSslStoreDetails(null, "classpath:tls/" + identity + ".crt", "classpath:tls/" + identity + ".key");
        SslManagerBundle managers = SslBundle.of(
                new PemSslStoreBundle(keyStore, PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))).getManagers();
        KeyManager[] keyManagers = Arrays.stream(managers.getKeyManagers())
                .map(km -> new PresentAnyway((X509ExtendedKeyManager) km, presented))
                .toArray(KeyManager[]::new);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers, managers.getTrustManagers(), null);
        return HttpClient.newBuilder()
                .sslContext(context)
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /**
     * The JDK withholds a client certificate whose issuer is not among the CAs the server names; this one sends it
     * anyway, so the server, not the client, has to refuse a foreign-CA certificate.
     */
    private static final class PresentAnyway extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager delegate;
        private final AtomicBoolean presented;

        PresentAnyway(X509ExtendedKeyManager delegate, AtomicBoolean presented) {
            this.delegate = delegate;
            this.presented = presented;
        }

        private String record(String alias) {
            if (alias != null) {
                presented.set(true);
            }
            return alias;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return record(delegate.chooseEngineClientAlias(keyType, null, engine));
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return record(delegate.chooseClientAlias(keyType, null, socket));
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, null);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseServerAlias(keyType, issuers, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
    }

    private static HttpResponse<String> get(HttpClient client, int port, String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + path))
                .timeout(Duration.ofSeconds(10))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
