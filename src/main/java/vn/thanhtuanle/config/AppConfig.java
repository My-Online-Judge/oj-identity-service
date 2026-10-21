package vn.thanhtuanle.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings.Redirects;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Duration;

@Configuration
public class AppConfig {

    /**
     * The client for Google's token endpoint, the service's only outbound HTTP call. Bounded: a stalled connection or
     * TLS handshake would otherwise hold a request thread for as long as the connection lives, and anyone can start
     * such calls. Redirects are not followed, so the form (client secret, code, verifier) goes to the configured token
     * URI only.
     */
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder,
                                     @Value("${oj.google.connect-timeout:5s}") Duration connectTimeout,
                                     @Value("${oj.google.read-timeout:10s}") Duration readTimeout) {
        return builder.connectTimeout(connectTimeout).readTimeout(readTimeout).redirects(Redirects.DONT_FOLLOW).build();
    }

    /** Time source for refresh rotation, token issue times and revocation cutoffs; tests replace it to step past the
     * reuse grace. */
    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }
}
