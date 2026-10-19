package vn.thanhtuanle.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** identity-service fetches its own JWKS over TLS from the port it listens on, whatever server.port says. */
class TlsProfileJwksUriTest {

    @Test
    void theJwksSelfUrlFollowsServerPort() throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        for (PropertySource<?> source : new YamlPropertySourceLoader()
                .load("application-tls.yml", new ClassPathResource("application-tls.yml"))) {
            environment.getPropertySources().addLast(source);
        }
        environment.getPropertySources().addFirst(new MapPropertySource("port", Map.of("server.port", "8443")));

        assertThat(environment.getProperty("oj.security.jwt.jwks-uri"))
                .isEqualTo("https://localhost:8443/.well-known/jwks.json");
    }
}
