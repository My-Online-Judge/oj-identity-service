package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.entity.User;

import java.util.HashSet;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * On identity's real schema (Flyway on Postgres): a handle is free when no live account has it in any case, the rows
 * V6's {@code ux_users_username_lower} covers.
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class HandleAllocatorOnPostgresTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void identityDb(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.flyway.enabled", () -> "true");
    }

    @Autowired HandleAllocator handleAllocator;
    @Autowired UserRepository userRepository;

    /** Letters only, so the display name "Alice <tag>" asks for the handle "alice_<tag>". */
    private static String tag() {
        return ThreadLocalRandom.current().ints(8, 'a', 'z' + 1)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
    }

    private void account(String username, UserStatus status) {
        userRepository.save(User.builder().username(username).name(username).email(username + "@example.com")
                .status(status.getValue()).roles(new HashSet<>()).build());
    }

    @Test
    void aTakenHandleGetsTheNextSuffix() {
        String tag = tag();
        account("Alice_" + tag, UserStatus.ACTIVE);

        assertThat(handleAllocator.allocate("Alice " + tag)).isEqualTo("alice_" + tag + "_2");
    }

    @Test
    void aDeletedAccountsNameDoesNotBlockIt() {
        String tag = tag();
        account("alice_" + tag, UserStatus.DELETED);

        assertThat(handleAllocator.allocate("Alice " + tag)).isEqualTo("alice_" + tag);
    }

    @Test
    void theCheckIgnoresCase() {
        String tag = tag();
        account("BOB_" + tag.toUpperCase(), UserStatus.DISABLED);

        assertThat(handleAllocator.allocate("bob " + tag)).isEqualTo("bob_" + tag + "_2");
    }
}
