package vn.thanhtuanle.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;

@Configuration
public class AppConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    /** Time source for refresh rotation; tests replace it to step past the reuse grace. */
    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}
