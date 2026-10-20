package vn.thanhtuanle.user;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import vn.thanhtuanle.auth.AuthService;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.exception.UniqueUserConstraints;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.web.error.AppException;

import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * On identity's real schema (Flyway V1–V6 on Postgres), V6's unique indexes are the last word on usernames and emails:
 * a case variant that the service's own (case-sensitive) checks let through is refused by the index, and the
 * violation answers 409 with the same message as those checks, not a 500.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class UserUniquenessOnPostgresTest {

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

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired AuthService authService;
    @Autowired TransactionTemplate transactionTemplate;

    /** Google's token endpoint. */
    @MockitoBean RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    String googleClientId;

    private static String unique(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static String createBody(String username, String email) {
        return """
                {"username":"%s","email":"%s","password":"Secret123"}""".formatted(username, email);
    }

    private User saved(String username, String email) {
        return userRepository.save(User.builder().username(username).name(username).email(email)
                .password("{noop}unused").status(UserStatus.ACTIVE.getValue()).roles(new HashSet<>()).build());
    }

    @Test
    @WithMockUser(authorities = "user:create")
    void createWithCaseVariantUsernameIs409() throws Exception {
        String username = unique("carol");
        saved(username, username + "@example.com");
        long accounts = userRepository.count();

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(username.toUpperCase(), unique("other") + "@example.com")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("Username already exists"));
        assertThat(userRepository.count()).isEqualTo(accounts);
    }

    @Test
    @WithMockUser(authorities = "user:create")
    void createWithCaseVariantEmailIs409() throws Exception {
        String email = unique("dave") + "@example.com";
        saved(unique("dave"), email);
        long accounts = userRepository.count();

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(unique("dave"), email.toUpperCase())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
        assertThat(userRepository.count()).isEqualTo(accounts);
    }

    @Test
    @WithMockUser(authorities = "user:update")
    void updateToACaseVariantEmailIs409() throws Exception {
        String email = unique("erin") + "@example.com";
        saved(unique("erin"), email);
        User other = saved(unique("frank"), unique("frank") + "@example.com");

        mockMvc.perform(put("/api/v1/users/" + other.getId()).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s"}""".formatted(email.toUpperCase())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
        assertThat(userRepository.findById(other.getId()).orElseThrow().getEmail()).isNotEqualToIgnoringCase(email);
    }

    /**
     * A Google sign-in that creates an account gets the index's reason too. Here a Google account signed up as
     * {@code dave.x@corp.example} (that is its username) and its email was changed since; a different Google account
     * with that address in another case finds no account by sub or email, and its new account's username collides.
     */
    @Test
    void aGoogleSignInWhoseUsernameIsTaken_isRefusedWithItsReason() {
        String taken = unique("grace") + "@corp.example";
        userRepository.save(User.builder().username(taken).name("Grace").email(unique("grace.new") + "@corp.example")
                .googleId(unique("sub")).status(UserStatus.ACTIVE.getValue()).roles(new HashSet<>()).build());
        long accounts = userRepository.count();
        String idToken = new PlainJWT(new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com").audience(googleClientId).subject(unique("sub"))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("nonce", "n-1").claim("email", taken.toUpperCase()).claim("email_verified", true)
                .claim("hd", "corp.example").build()).serialize();
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(ExchangeTokenResponse.builder().idToken(idToken).build()));

        assertThatThrownBy(() -> authService.authenticateGoogleUser("code", "verifier", "n-1",
                new ClientMeta("10.0.0.8", "dev-8", "pg/1.0")))
                .isInstanceOfSatisfying(AppException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo(ErrorCode.USERNAME_EXISTED));
        assertThat(userRepository.count()).isEqualTo(accounts);
    }

    /** Google's token endpoint answers with a verified id token for this Google account. */
    private void googleAnswersFor(String sub, String email) {
        String idToken = new PlainJWT(new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com").audience(googleClientId).subject(sub)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("nonce", "n-1").claim("email", email).claim("email_verified", true).build()).serialize();
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(ExchangeTokenResponse.builder().idToken(idToken).build()));
    }

    /**
     * V6 counts live accounts only, so a soft-deleted account may keep the exact username of a live one. Here a Google
     * account signed up as {@code kate@uni.edu.vn}, had its email changed, and was soft-deleted; another Google account
     * with that address signs up and gets the same username. A lookup by username sees only the live account, so the
     * new account's own requests (and its next sign-in) work.
     */
    @Test
    void aGoogleAccountWithTheUsernameOfADeletedAccount_isTheOneItsUsernameFinds() {
        String address = unique("kate") + "@uni.edu.vn";
        userRepository.save(User.builder().username(address).name("Kate").email(unique("kate.new") + "@uni.edu.vn")
                .googleId(unique("sub")).status(UserStatus.DELETED.getValue()).roles(new HashSet<>()).build());
        String sub = unique("sub");
        googleAnswersFor(sub, address);
        ClientMeta meta = new ClientMeta("10.0.0.9", "dev-9", "pg/1.0");

        assertThat(authService.authenticateGoogleUser("code", "verifier", "n-1", meta).getAccessToken()).isNotNull();

        assertThat(userRepository.findByUsername(address)).get()
                .extracting(User::getGoogleId, User::getStatus)
                .containsExactly(sub, UserStatus.ACTIVE.getValue());
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(address, null, List.of()));
        try {
            assertThat(authService.me().getUsername()).isEqualTo(address);
        } finally {
            SecurityContextHolder.clearContext();
        }
        assertThat(authService.authenticateGoogleUser("code", "verifier", "n-1", meta).getAccessToken()).isNotNull();
    }

    /**
     * A change to a managed row is written only at commit (a Google link setting google_id, for one). The index's
     * refusal then still reaches the caller as a DataIntegrityViolationException naming the index, which is what the
     * Google sign-in maps to its reason.
     */
    @Test
    void aViolationFoundOnlyAtCommitIsMappedToo() {
        String email = unique("hank") + "@example.com";
        saved(unique("hank"), email);
        User other = saved(unique("ivan"), unique("ivan") + "@example.com");

        assertThatThrownBy(() -> transactionTemplate.executeWithoutResult(status ->
                userRepository.lockById(other.getId()).orElseThrow().setEmail(email.toUpperCase())))
                .isInstanceOfSatisfying(DataIntegrityViolationException.class,
                        e -> assertThat(UniqueUserConstraints.toErrorCode(e)).contains(ErrorCode.EMAIL_EXISTED));
    }
}
