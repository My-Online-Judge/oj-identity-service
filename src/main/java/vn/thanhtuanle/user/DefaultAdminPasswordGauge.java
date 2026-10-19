package vn.thanhtuanle.user;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 1 while the root admin still has the published seed password, else 0 (also 0 with no admin user).
 * Evaluated at startup and after each password change, never on scrape: bcrypt costs ~100 ms.
 */
@Component
public class DefaultAdminPasswordGauge {

    static final String SEED_PASSWORD = "Admin@12345";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AtomicInteger value = new AtomicInteger();

    public DefaultAdminPasswordGauge(UserRepository userRepository, PasswordEncoder passwordEncoder,
            MeterRegistry registry) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        Gauge.builder("oj.identity.default.admin.password", value, AtomicInteger::get)
                .description("1 while user 'admin' still has the published seed password")
                .register(registry);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void refresh() {
        value.set(userRepository.findByUsername("admin")
                .map(u -> u.getPassword() != null && passwordEncoder.matches(SEED_PASSWORD, u.getPassword()))
                .orElse(false) ? 1 : 0);
    }
}
