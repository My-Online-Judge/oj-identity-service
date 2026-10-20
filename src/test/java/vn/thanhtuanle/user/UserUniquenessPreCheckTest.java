package vn.thanhtuanle.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.entity.User;

import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The service's own checks of a new username or email match V6's unique indexes: case-insensitive, and only live
 * accounts (status not 2) count. The test profile's H2 schema has no V6 index, so every 409 here comes from those
 * checks, and every success shows that nothing in them refused (V6 itself is covered by UserUniquenessOnPostgresTest).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserUniquenessPreCheckTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;

    private static String unique(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static String createBody(String username, String email) {
        return """
                {"username":"%s","email":"%s","password":"Secret123"}""".formatted(username, email);
    }

    private User saved(String username, String email, UserStatus status) {
        return userRepository.save(User.builder().username(username).name(username).email(email)
                .password("{noop}unused").status(status.getValue()).roles(new HashSet<>()).build());
    }

    @Test
    @WithMockUser(authorities = "user:create")
    void aCaseVariantOfALiveUsernameIs409() throws Exception {
        String username = unique("carol");
        saved(username, unique("carol") + "@example.com", UserStatus.ACTIVE);
        long accounts = userRepository.count();

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(username.toUpperCase(), unique("other") + "@example.com")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username already exists"));
        assertThat(userRepository.count()).isEqualTo(accounts);
    }

    @Test
    @WithMockUser(authorities = "user:create")
    void aCaseVariantOfALiveEmailIs409() throws Exception {
        String email = unique("dave") + "@example.com";
        saved(unique("dave"), email, UserStatus.DISABLED);
        long accounts = userRepository.count();

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(unique("dave"), email.toUpperCase())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
        assertThat(userRepository.count()).isEqualTo(accounts);
    }

    @Test
    @WithMockUser(authorities = "user:update")
    void anUpdateToACaseVariantOfALiveEmailIs409() throws Exception {
        String email = unique("erin") + "@example.com";
        saved(unique("erin"), email, UserStatus.ACTIVE);
        User other = saved(unique("frank"), unique("frank") + "@example.com", UserStatus.ACTIVE);

        mockMvc.perform(put("/api/v1/users/" + other.getId()).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s"}""".formatted(email.toUpperCase())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
        assertThat(userRepository.findById(other.getId()).orElseThrow().getEmail()).isNotEqualToIgnoringCase(email);
    }

    @Test
    @WithMockUser(authorities = "user:create")
    void theUsernameAndEmailOfADeletedAccountCanBeTakenAgain() throws Exception {
        String username = unique("gina");
        String email = username + "@example.com";
        saved(username, email, UserStatus.DELETED);

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(username, email)))
                .andExpect(status().is2xxSuccessful());
        assertThat(userRepository.findAll()).filteredOn(u -> username.equals(u.getUsername()))
                .extracting(User::getStatus)
                .containsExactlyInAnyOrder(UserStatus.DELETED.getValue(), UserStatus.ACTIVE.getValue());
    }

    @Test
    @WithMockUser(authorities = "user:update")
    void anUpdateToTheEmailOfADeletedAccountIsAllowed() throws Exception {
        String email = unique("hank") + "@example.com";
        saved(unique("hank"), email, UserStatus.DELETED);
        User other = saved(unique("ivan"), unique("ivan") + "@example.com", UserStatus.ACTIVE);

        mockMvc.perform(put("/api/v1/users/" + other.getId()).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s"}""".formatted(email)))
                .andExpect(status().is2xxSuccessful());
        assertThat(userRepository.findById(other.getId()).orElseThrow().getEmail()).isEqualTo(email);
    }
}
