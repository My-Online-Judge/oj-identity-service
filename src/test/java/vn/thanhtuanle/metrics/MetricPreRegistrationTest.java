package vn.thanhtuanle.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import vn.thanhtuanle.security.LoginRateLimiter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards that each rate limiter holds its Micrometer counter (built in the constructor), so an
 * accidental revert to a per-increment {@code registry.counter(...)} lookup is caught.
 *
 * <p>IMPORTANT — this does NOT prove the counter is visible at 0 in production. It once claimed to,
 * but that was wrong: in the live stack (Spring Boot 3.4 / Micrometer 1.14 / prometheus-metrics-core)
 * an oj_* counter idling at 0 is dropped from the scrape and only reappears once it increments —
 * {@link SimpleMeterRegistry} used here does not reproduce that. The real guarantee that alerts still
 * behave on an absent/zero series lives in judge-deployment/alerts_test.yml (the `or vector(0)`
 * guards), not here. See the ops memory for the full investigation.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MetricPreRegistrationTest {

    @Mock StringRedisTemplate redis;

    MeterRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
    }

    @Test
    void loginRateLimiterHoldsItsCounter() {
        new LoginRateLimiter(redis, registry);

        assertThat(registry.find("oj.login.rate_limited").counter()).isNotNull();
    }

}
