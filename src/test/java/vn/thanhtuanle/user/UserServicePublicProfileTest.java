package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;
import vn.thanhtuanle.oj.common.web.error.ResourceNotFoundException;
import vn.thanhtuanle.user.dto.PublicProfileResponse;

import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Public profiles on identity's real schema (Flyway V1-V6 on Postgres): V6 lets a soft-deleted account keep the name
 * of a live one, so the lookup must see live rows only, and case is folded with {@code lower()} like the index.
 */
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
@Import(UserServicePublicProfileTest.PublicKeyDecoder.class)
class UserServicePublicProfileTest {

    @TestConfiguration
    static class PublicKeyDecoder {
        @Bean
        JwtDecoder testJwtDecoder(JwtUtil jwtUtil) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtUtil.getPublicKey()).build();
            decoder.setJwtValidator(OjJwtDecoders.validator());
            return decoder;
        }
    }

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

    @Autowired UserService userService;
    @Autowired UserRepository userRepository;

    private static String unique(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private User saved(String username, int status) {
        return userRepository.save(User.builder().username(username).name("Name " + username).avatar("av.png")
                .email(unique("mail") + "@example.com").password("{noop}unused").status(status)
                .roles(new HashSet<>()).build());
    }

    /** A Google sign-up: its username is its email address (AuthService.newAccount). */
    private User googleStyle() {
        String email = unique("student") + "@gmail.com";
        return userRepository.save(User.builder().username(email).name("Student").avatar("g.png").email(email)
                .googleId(unique("sub")).status(UserStatus.ACTIVE.getValue()).roles(new HashSet<>()).build());
    }

    @Test
    void lookupIgnoresCase() {
        String username = unique("Alice");
        User alice = saved(username, UserStatus.ACTIVE.getValue());

        PublicProfileResponse profile = userService.publicProfile(username.toUpperCase());

        assertThat(profile.id()).isEqualTo(alice.getId());
        assertThat(profile.username()).isEqualTo(username);
        assertThat(profile.name()).isEqualTo("Name " + username);
        assertThat(profile.avatar()).isEqualTo("av.png");
        assertThat(profile.createdAt()).isNotNull();
    }

    @Test
    void deletedUserIsNotFound() {
        String username = unique("gone");
        saved(username, UserStatus.DELETED.getValue());

        assertThatThrownBy(() -> userService.publicProfile(username))
                .isInstanceOfSatisfying(ResourceNotFoundException.class,
                        e -> assertThat(e.getMessage()).isEqualTo("User not found"));
    }

    @Test
    void unknownUserIsNotFound() {
        assertThatThrownBy(() -> userService.publicProfile(unique("nobody")))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void disabledUserIsFound() {
        String username = unique("muted");
        saved(username, UserStatus.DISABLED.getValue());

        assertThat(userService.publicProfile(username).username()).isEqualTo(username);
    }

    @Test
    void aDeletedNameNowUsedByALiveAccountResolvesToTheLiveOne() {
        String username = unique("Kate");
        saved(username, UserStatus.DELETED.getValue());
        User live = saved(username.toLowerCase(), UserStatus.ACTIVE.getValue());

        assertThat(userService.publicProfile(username).id()).isEqualTo(live.getId());
    }

    @Test
    void batchLeavesOutDeletedAndUnknownUsers() {
        User a = saved(unique("a"), UserStatus.ACTIVE.getValue());
        User d = saved(unique("d"), UserStatus.DISABLED.getValue());
        User gone = saved(unique("g"), UserStatus.DELETED.getValue());

        List<PublicProfileResponse> found = userService.publicProfiles(
                List.of(a.getId(), d.getId(), gone.getId(), UUID.randomUUID()));

        assertThat(found).extracting(PublicProfileResponse::id).containsExactlyInAnyOrder(a.getId(), d.getId());
    }

    @Test
    void anEmailShapedUsernameIsNeverInTheProfile() {
        User student = googleStyle();

        PublicProfileResponse profile = userService.publicProfile(student.getUsername());

        assertThat(profile.id()).isEqualTo(student.getId());
        assertThat(profile.username()).isNull();
        assertThat(profile.name()).isEqualTo("Student");
        assertThat(profile.avatar()).isEqualTo("g.png");
        assertThat(profile.createdAt()).isNotNull();
    }

    @Test
    void anEmailShapedUsernameIsNeverInTheBatchWhileANormalOneIsKept() {
        User student = googleStyle();
        String handle = unique("bob");
        User bob = saved(handle, UserStatus.ACTIVE.getValue());

        List<PublicProfileResponse> found = userService.publicProfiles(List.of(student.getId(), bob.getId()));

        assertThat(found)
                .extracting(PublicProfileResponse::id, PublicProfileResponse::username, PublicProfileResponse::name)
                .containsExactlyInAnyOrder(
                        tuple(student.getId(), null, "Student"),
                        tuple(bob.getId(), handle, "Name " + handle));
    }
}
