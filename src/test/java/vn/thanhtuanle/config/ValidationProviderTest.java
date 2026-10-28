package vn.thanhtuanle.config;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import vn.thanhtuanle.auth.dto.LoginRequest;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The DTO constraints (LoginRequest's {@code @Size(max = 64)} bounds the limiter's Redis keys) only run when a Bean
 * Validation provider is on the classpath. It used to arrive only through springdoc, which happens to depend on it: the
 * starter is declared in this pom, so dropping springdoc cannot silently switch every constraint off.
 */
class ValidationProviderTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    private static LoginRequest login(String username, String password) {
        LoginRequest request = new LoginRequest();
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }

    @Test
    void aUsernameLongerThanTheAuditColumnIsAViolation() {
        assertThat(validator.validate(login("u".repeat(65), "secret"))).hasSize(1);
    }

    @Test
    void aBlankUsernameOrPasswordIsAViolation() {
        assertThat(validator.validate(login(" ", "secret"))).isNotEmpty();
        assertThat(validator.validate(login("alice", ""))).isNotEmpty();
    }

    @Test
    void aUsernameOfExactlyTheLimitIsAccepted() {
        assertThat(validator.validate(login("u".repeat(64), "secret"))).isEmpty();
    }

    @Test
    void thePomDeclaresTheValidationStarterItself() throws Exception {
        assertThat(Files.readString(Path.of("pom.xml")))
                .containsPattern("(?s)<dependency>\\s*<groupId>org\\.springframework\\.boot</groupId>\\s*"
                        + "<artifactId>spring-boot-starter-validation</artifactId>");
    }
}
