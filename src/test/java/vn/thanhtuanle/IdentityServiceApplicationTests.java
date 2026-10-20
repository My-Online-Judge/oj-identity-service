package vn.thanhtuanle;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class IdentityServiceApplicationTests {

	@Autowired
	RestTemplate restTemplate;

	@Test
	void contextLoads() {
	}

	/** The client that calls Google's token endpoint never waits forever: 5 s to connect, 10 s for the answer. */
	@Test
	void theGoogleClientHasTimeoutsByDefault() {
		JdkClientHttpRequestFactory factory = (JdkClientHttpRequestFactory) restTemplate.getRequestFactory();
		HttpClient client = (HttpClient) ReflectionTestUtils.getField(factory, "httpClient");

		assertThat(client.connectTimeout()).contains(Duration.ofSeconds(5));
		assertThat(ReflectionTestUtils.getField(factory, "readTimeout")).isEqualTo(Duration.ofSeconds(10));
	}

}
