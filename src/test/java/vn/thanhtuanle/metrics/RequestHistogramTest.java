package vn.thanhtuanle.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * HighLatency alerts on {@code histogram_quantile} over {@code http_server_requests_seconds_bucket}, so the
 * timer must publish buckets. Without {@code percentiles-histogram} it exports only count, sum and max.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
@ActiveProfiles("test")
class RequestHistogramTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private MeterRegistry registry;

    @Test
    void httpServerRequestsPublishesHistogramBuckets() throws Exception {
        mockMvc.perform(get("/actuator/health"));

        var timer = registry.find("http.server.requests").timer();
        assertThat(timer).isNotNull();
        assertThat(timer.takeSnapshot().histogramCounts()).isNotEmpty();
    }
}
