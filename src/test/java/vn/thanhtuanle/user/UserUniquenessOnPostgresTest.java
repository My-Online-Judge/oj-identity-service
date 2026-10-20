package vn.thanhtuanle.user;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import vn.thanhtuanle.auth.TokenHasher;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.exception.UniqueUserConstraints;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.JwtUtil;
import vn.thanhtuanle.entity.Token;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;
import vn.thanhtuanle.oj.common.web.error.AppException;
import vn.thanhtuanle.repository.TokenRepository;

import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * On identity's real schema (Flyway V1–V6 on Postgres), V6's unique indexes are the last word on usernames and emails:
 * a case variant is refused (by the service's own checks, which match the indexes, or by an index when a write gets
 * past them, as a Google sign-in's can) with 409 and the same message either way, not a 500. A soft-deleted account's
 * username and email may be taken again.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
@Import(UserUniquenessOnPostgresTest.PublicKeyDecoder.class)
class UserUniquenessOnPostgresTest {

    /** Real access tokens through the real filter: keyed with identity's public key (MockMvc has no JWKS server). */
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

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired AuthService authService;
    @Autowired TransactionTemplate transactionTemplate;
    @Autowired TokenRepository tokenRepository;
    @Autowired JwtUtil jwtUtil;
    @Autowired JdbcTemplate jdbc;

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

    @Test
    @WithMockUser(authorities = "user:create")
    void theUsernameAndEmailOfADeletedAccountCanBeTakenAgain() throws Exception {
        String username = unique("judy");
        String email = username + "@example.com";
        userRepository.save(User.builder().username(username).name(username).email(email).password("{noop}unused")
                .status(UserStatus.DELETED.getValue()).roles(new HashSet<>()).build());
        long accounts = userRepository.count();

        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content(createBody(username, email)))
                .andExpect(status().is2xxSuccessful());
        assertThat(userRepository.count()).isEqualTo(accounts + 1);
        // Its login resolves the new account, not the deleted one.
        assertThat(userRepository.findByUsername(username)).get()
                .extracting(User::getStatus).isEqualTo(UserStatus.ACTIVE.getValue());
    }

    /**
     * Reviving a soft-deleted account (its status set back to active) whose username a live account has taken since:
     * the index refuses it at commit, and the admin gets the 409, not a 500.
     */
    @Test
    void reviving_aDeletedAccountWhoseUsernameIsTakenNow_is409() throws Exception {
        User admin = saved(unique("undelete_admin"), unique("admin") + "@example.com");
        String username = unique("lena");
        User deleted = userRepository.save(User.builder().username(username).name(username)
                .email(unique("lena.old") + "@example.com").password("{noop}unused")
                .status(UserStatus.DELETED.getValue()).roles(new HashSet<>()).build());
        saved(username.toUpperCase(), unique("lena.new") + "@example.com");

        mockMvc.perform(patch("/api/v1/users/" + deleted.getId() + "/status").contentType(MediaType.APPLICATION_JSON)
                        .with(jwt().jwt(token -> token.claim("uid", admin.getId().toString()))
                                .authorities(new SimpleGrantedAuthority("user:update")))
                        .content("""
                                {"status":1}"""))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username already exists"));
        assertThat(userRepository.findById(deleted.getId()).orElseThrow().getStatus())
                .isEqualTo(UserStatus.DELETED.getValue());
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
                .thenReturn(ResponseEntity.ok(new ExchangeTokenResponse(null, null, null, null, null, idToken)));

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
                .thenReturn(ResponseEntity.ok(new ExchangeTokenResponse(null, null, null, null, null, idToken)));
    }

    /**
     * V6 counts live accounts only, so a soft-deleted account may keep the exact username of a live one. Here a Google
     * account signed up as {@code kate@uni.edu.vn}, had its email changed, and was soft-deleted; another Google account
     * with that address signs up and gets the same username. A lookup by username sees only the live account, so the
     * new account's own requests (and its next sign-in) work.
     */
    @Test
    void aGoogleAccountWithTheUsernameOfADeletedAccount_isTheOneItsUsernameFinds() throws Exception {
        String address = unique("kate") + "@uni.edu.vn";
        userRepository.save(User.builder().username(address).name("Kate").email(unique("kate.new") + "@uni.edu.vn")
                .googleId(unique("sub")).status(UserStatus.DELETED.getValue()).roles(new HashSet<>()).build());
        String sub = unique("sub");
        googleAnswersFor(sub, address);
        ClientMeta meta = new ClientMeta("10.0.0.9", "dev-9", "pg/1.0");

        String accessToken = authService.authenticateGoogleUser("code", "verifier", "n-1", meta).getAccessToken();

        assertThat(userRepository.findByUsername(address)).get()
                .extracting(User::getGoogleId, User::getStatus)
                .containsExactly(sub, UserStatus.ACTIVE.getValue());
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value(address))
                .andExpect(jsonPath("$.data.googleId").value(sub));
        assertThat(authService.authenticateGoogleUser("code", "verifier", "n-1", meta).getAccessToken()).isNotNull();
    }

    /**
     * An admin soft-deleted an account and its revocation write failed (Redis was down a moment), then a new account
     * took the same username. The deleted account's access token is still valid and names it by username ({@code sub})
     * and by id ({@code uid}): identity resolves the caller by id, so the token acts as nobody, never as the new
     * account. Its /auth/me is 401, its password change is 401, and its logout ends none of the new account's sessions.
     */
    @Test
    void aStillValidTokenOfADeletedAccount_whoseUsernameWasTakenAgain_actsAsNobody() throws Exception {
        String username = unique("mia");
        User deleted = userRepository.save(User.builder().username(username).name("Mia").password("{noop}unused")
                .email(unique("mia.old") + "@example.com").status(UserStatus.DELETED.getValue())
                .roles(new HashSet<>()).build());
        String token = jwtUtil.generateToken(deleted);
        User reused = saved(username, unique("mia.new") + "@example.com");
        tokenRepository.save(Token.builder().user(reused).token(TokenHasher.sha256Hex(unique("refresh")))
                .tokenType(TokenType.REFRESH).build());

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(put("/api/v1/users/me/password").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword":"Unused123","newPassword":"Changed123"}"""))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        assertThat(jdbc.queryForObject("select count(*) from t_tokens where user_id = ?", Long.class, reused.getId()))
                .as("the new account's sessions").isEqualTo(1);
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
