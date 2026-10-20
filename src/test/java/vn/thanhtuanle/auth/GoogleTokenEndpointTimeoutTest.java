package vn.thanhtuanle.auth;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The call to Google's token endpoint is bounded. A Google that accepts the connection and never answers (a stalled
 * path, a TLS handshake that never completes) ends the login with the usual failed redirect, instead of pinning a
 * request thread for as long as the connection lives. Here the endpoint is a local socket that accepts and never writes,
 * so the client's TLS handshake waits for a ServerHello that never comes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GoogleTokenEndpointTimeoutTest {

    private static final List<Socket> HELD = new CopyOnWriteArrayList<>();
    private static final ServerSocket STALLED_GOOGLE = openStalledEndpoint();

    @Autowired MockMvc mockMvc;
    @Autowired RestTemplate restTemplate;

    private static ServerSocket openStalledEndpoint() {
        try {
            ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread acceptor = new Thread(() -> {
                while (!server.isClosed()) {
                    try {
                        HELD.add(server.accept());
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "stalled-google");
            acceptor.setDaemon(true);
            acceptor.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void stalledGoogle(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.provider.google.token-uri",
                () -> "https://127.0.0.1:" + STALLED_GOOGLE.getLocalPort() + "/token");
        registry.add("oj.google.connect-timeout", () -> "300ms");
        registry.add("oj.google.read-timeout", () -> "300ms");
    }

    @AfterAll
    static void closeTheEndpoint() throws IOException {
        for (Socket socket : HELD) {
            socket.close();
        }
        STALLED_GOOGLE.close();
    }

    @Test
    void aGoogleThatNeverAnswersEndsTheLoginInBoundedTime() {
        long start = System.nanoTime();
        MvcResult result = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> mockMvc.perform(
                        get("/api/v1/auth/outbound/google/callback").param("code", "the-code").param("state", "s-1")
                                .cookie(new Cookie("oauthState", "s-1"), new Cookie("oauthVerifier", "v-1"),
                                        new Cookie("oauthNonce", "n-1")))
                .andReturn());
        Duration took = Duration.ofNanos(System.nanoTime() - start);

        assertThat(result.getResponse().getRedirectedUrl())
                .isEqualTo("http://localhost:5173/problems?login=failed&reason=UNCATEGORIZED_EXCEPTION");
        assertThat(result.getResponse().getCookie("accessToken")).isNull();
        assertThat(took).isLessThan(Duration.ofSeconds(2));
        // The exchange really reached the stalled endpoint, and gave up on it.
        assertThat(HELD).isNotEmpty();
    }

    @Test
    void theClientIsBuiltWithTheConfiguredTimeouts_andFollowsNoRedirect() {
        JdkClientHttpRequestFactory factory = (JdkClientHttpRequestFactory) restTemplate.getRequestFactory();
        HttpClient client = (HttpClient) ReflectionTestUtils.getField(factory, "httpClient");

        assertThat(client.connectTimeout()).contains(Duration.ofMillis(300));
        assertThat(ReflectionTestUtils.getField(factory, "readTimeout")).isEqualTo(Duration.ofMillis(300));
        // The form carries the client secret: it goes to the configured token URI and nowhere else.
        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
    }
}
