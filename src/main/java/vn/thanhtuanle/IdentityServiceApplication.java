package vn.thanhtuanle;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.TimeZone;

@SpringBootApplication
@EnableAsync
@EnableScheduling
public class IdentityServiceApplication {

	public static void main(String[] args) {
		// Run the whole app in Vietnam time (GMT+7). Entities audit createdAt/updatedAt as naive
		// LocalDateTime via LocalDateTime.now(), which reads the JVM default zone — in Docker that is
		// UTC unless pinned here. Set before SpringApplication.run so auditing and logs both use it.
		// Uses the JRE's bundled tz database, so it works even on the alpine image (no OS tzdata).
		TimeZone.setDefault(TimeZone.getTimeZone("Asia/Ho_Chi_Minh"));
		SpringApplication.run(IdentityServiceApplication.class, args);
	}

}
