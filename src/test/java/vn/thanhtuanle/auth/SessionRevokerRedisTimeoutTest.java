package vn.thanhtuanle.auth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With Redis down, the after-commit revocation write must give up in about a second, not hold the
 * admin's request (and its JDBC connection) for Lettuce's 60 s default. Uses this service's own
 * application.yml Redis settings against a stand-in that accepts connections and never replies.
 */
class SessionRevokerRedisTimeoutTest {

    private static ServerSocket silentRedis;
    private static final List<Socket> accepted = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void start() throws IOException {
        silentRedis = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            while (!silentRedis.isClosed()) {
                try {
                    accepted.add(silentRedis.accept());
                } catch (IOException closed) {
                    return;
                }
            }
        }, "silent-redis");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @AfterAll
    static void stop() throws IOException {
        silentRedis.close();
        for (Socket connection : accepted) {
            connection.close();
        }
    }

    @Test
    void aSilentRedisCostsTheRevocationWriteAboutASecond() {
        new ApplicationContextRunner()
                .withInitializer(new ConfigDataApplicationContextInitializer())
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class))
                .withPropertyValues("spring.data.redis.host=127.0.0.1",
                        "spring.data.redis.port=" + silentRedis.getLocalPort())
                .run(context -> {
                    SessionRevoker revoker = new SessionRevoker(context.getBean(StringRedisTemplate.class), 900_000L);
                    long start = System.nanoTime();

                    // Outside a transaction the write happens right away; it fails and is only logged.
                    revoker.revokeAccessTokensAfterCommit(List.of(UUID.randomUUID()));

                    assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(3));
                });
    }
}
