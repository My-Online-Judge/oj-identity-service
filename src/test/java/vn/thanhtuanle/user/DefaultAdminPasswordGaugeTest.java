package vn.thanhtuanle.user;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.thanhtuanle.entity.User;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DefaultAdminPasswordGaugeTest {

    @Mock UserRepository userRepository;

    PasswordEncoder encoder = new BCryptPasswordEncoder(4);
    MeterRegistry registry = new SimpleMeterRegistry();
    DefaultAdminPasswordGauge gauge;

    @BeforeEach
    void setUp() {
        gauge = new DefaultAdminPasswordGauge(userRepository, encoder, registry);
    }

    private double value() {
        return registry.get("oj.identity.default.admin.password").gauge().value();
    }

    private User admin(String hash) {
        return User.builder().username("admin").password(hash).build();
    }

    @Test
    void oneWhileDefault() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(admin(encoder.encode("Admin@12345"))));
        gauge.refresh();
        assertThat(value()).isEqualTo(1.0);
    }

    @Test
    void zeroAfterChange() {
        User admin = admin(encoder.encode("Admin@12345"));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(admin));
        gauge.refresh();
        assertThat(value()).isEqualTo(1.0);

        admin.setPassword(encoder.encode("Another1Pass"));
        gauge.refresh();
        assertThat(value()).isEqualTo(0.0);
    }

    @Test
    void zeroWithoutAdmin() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        gauge.refresh();
        assertThat(value()).isEqualTo(0.0);
    }
}
