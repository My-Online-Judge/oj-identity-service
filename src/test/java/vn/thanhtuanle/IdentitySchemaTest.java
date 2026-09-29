package vn.thanhtuanle;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.permission.PermissionRepository;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * identity-db is built by Flyway alone: V1 (the live schema) + V2 (the seed). The context starting
 * at all proves Hibernate's ddl-auto=validate accepts V1 for every identity entity; the assertions
 * prove a fresh database is usable (every permission, the system roles, the root admin).
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class IdentitySchemaTest {

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

    @Autowired
    PermissionRepository permissions;
    @Autowired
    RoleRepository roles;
    @Autowired
    UserRepository users;

    @Test
    @Transactional
    void aFreshIdentityDbMatchesTheEntitiesAndIsUsable() {
        assertThat(permissions.count()).isEqualTo(17);
        assertThat(roles.findAll()).extracting(Role::getName)
                .containsExactlyInAnyOrder("USER", "ADMIN", "SYS_ROOT");
        assertThat(roles.findByName("SYS_ROOT").orElseThrow().getPermissions()).hasSize(17);

        User admin = users.findByUsername("admin").orElseThrow();
        assertThat(admin.getStatus()).isEqualTo(1);
        assertThat(admin.getRoles()).extracting(Role::getName).containsExactlyInAnyOrder("ADMIN", "SYS_ROOT");
    }
}
