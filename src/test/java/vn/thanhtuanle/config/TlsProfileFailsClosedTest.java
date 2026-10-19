package vn.thanhtuanle.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** With the tls profile and no certificate files the service must fail at startup, never fall back to plaintext. */
class TlsProfileFailsClosedTest {

    @Test
    void missingCertificateFilesFailTheStartup() {
        assertThatThrownBy(() -> new SpringApplicationBuilder(vn.thanhtuanle.IdentityServiceApplication.class)
                .profiles("test", "tls")
                // Arguments outrank application.yml, whose active profile (dev) would otherwise bring in a datasource
                // that needs DATABASE_URL and fail before the SSL bundle is read.
                .run("--spring.profiles.active=test,tls", "--OJ_TLS_DIR=/nonexistent", "--spring.jpa.hibernate.ddl-auto=none", "--server.port=0", "--management.server.port=0"))
                .satisfies(e -> {
                    StringBuilder chain = new StringBuilder();
                    for (Throwable t = e; t != null; t = t.getCause()) {
                        chain.append(t.getMessage()).append('\n');
                    }
                    assertThat(chain.toString()).contains("/nonexistent/tls.crt");
                });
    }
}
