package vn.thanhtuanle.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.RestTemplate;
import vn.thanhtuanle.auth.dto.ExchangeTokenResponse;
import vn.thanhtuanle.common.enums.UserStatus;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.security.LoginAttemptRepository;
import vn.thanhtuanle.user.RoleRepository;
import vn.thanhtuanle.user.UserRepository;

import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Google sign-ins end to end through the callback, on H2 with the real account rules and the real login audit. Only
 * Google's token endpoint is a mock.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GoogleLoginIntegrationTest {

    private static final String APP = "http://localhost:5173";
    private static final String NONCE = "integration-nonce";

    @Autowired MockMvc mockMvc;
    @Autowired LoginAttemptRepository loginAttemptRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired UserRepository userRepository;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    String googleClientId;

    /** Google's token endpoint. */
    @MockitoBean RestTemplate restTemplate;

    /** H2 is built from the entities, without Flyway's seed: a new Google account needs the USER role. */
    @BeforeEach
    void seedTheUserRole() {
        if (roleRepository.findByName("USER").isEmpty()) {
            roleRepository.save(Role.builder().name("USER").description("Regular user").build());
        }
    }

    /** Google answers the code exchange with an id token for this verified identity. */
    private void googleSignsIn(JWTClaimsSet.Builder claims) {
        String idToken = new PlainJWT(claims
                .issuer("https://accounts.google.com")
                .audience(googleClientId)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("nonce", NONCE)
                .claim("email_verified", true)
                .build()).serialize();
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(ExchangeTokenResponse.class)))
                .thenReturn(ResponseEntity.ok(ExchangeTokenResponse.builder().idToken(idToken).build()));
    }

    private static JWTClaimsSet.Builder identity(String sub, String email) {
        return new JWTClaimsSet.Builder().subject(sub).claim("email", email);
    }

    /** The browser comes back from Google with the code and the state, carrying the outbound call's three cookies. */
    private MvcResult callback() throws Exception {
        return mockMvc.perform(get("/api/v1/auth/outbound/google/callback").param("code", "the-code")
                        .param("state", "state-1")
                        .cookie(new Cookie("oauthState", "state-1"), new Cookie("oauthVerifier", "verifier-1"),
                                new Cookie("oauthNonce", NONCE)))
                .andReturn();
    }

    /** An account an admin created: a password, no Google id. */
    private User account(String email, UserStatus status) {
        String username = "u_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(User.builder().username(username).name(username).email(email)
                .password("{noop}unused").status(status.getValue()).roles(new HashSet<>()).build());
    }

    /** Every account whose email is this one, whatever its case. */
    private List<User> accountsWithEmail(String email) {
        return userRepository.findAll().stream().filter(u -> email.equalsIgnoreCase(u.getEmail())).toList();
    }

    private static String uniqueEmail(String domain) {
        return "user." + UUID.randomUUID().toString().substring(0, 8) + "@" + domain;
    }

    private static void assertSignedIn(MvcResult result) {
        assertThat(result.getResponse().getRedirectedUrl()).isEqualTo(APP + "/problems?login=ok");
        assertThat(result.getResponse().getCookie("accessToken").getValue()).isNotBlank();
        assertThat(result.getResponse().getCookie("refreshToken").getValue()).isNotBlank();
    }

    @Test
    void aVerifiedSeventyCharacterEmailSignsInAndGetsCookies() throws Exception {
        // A Workspace address longer than the audit's varchar(64) username column.
        String domain = "@student.example-university.edu.vn";
        String email = ("long." + UUID.randomUUID().toString().replace("-", "")).substring(0, 70 - domain.length())
                + domain;
        assertThat(email).hasSize(70);
        googleSignsIn(identity("sub-" + UUID.randomUUID(), email));

        assertSignedIn(callback());
        // The audit kept what fits; it never fails the login it records.
        assertThat(loginAttemptRepository.findAll()).extracting(LoginAttempt::getUsername)
                .contains(email.substring(0, 64));
    }

    @Test
    void anEmailInAnotherCaseSignsInToTheSameAccount() throws Exception {
        String email = uniqueEmail("example.com");
        User account = account(email.toUpperCase(), UserStatus.ACTIVE);
        String sub = "sub-" + UUID.randomUUID();
        googleSignsIn(identity(sub, email).claim("hd", "example.com"));

        assertSignedIn(callback());
        assertThat(accountsWithEmail(email)).singleElement().satisfies(u -> {
            assertThat(u.getId()).isEqualTo(account.getId());
            assertThat(u.getGoogleId()).isEqualTo(sub);
        });
    }

    /** V6 lets a soft-deleted account keep the email of a live one: the live one signs in. */
    @Test
    void aLiveAndADeletedAccountWithTheEmail_signInToTheLiveOne() throws Exception {
        String email = uniqueEmail("example.com");
        User deleted = account(email, UserStatus.DELETED);
        User live = account(email, UserStatus.ACTIVE);
        String sub = "sub-" + UUID.randomUUID();
        googleSignsIn(identity(sub, email).claim("hd", "example.com"));

        assertSignedIn(callback());
        assertThat(userRepository.findById(live.getId()).orElseThrow().getGoogleId()).isEqualTo(sub);
        assertThat(userRepository.findById(deleted.getId()).orElseThrow().getGoogleId()).isNull();
        assertThat(accountsWithEmail(email)).hasSize(2);
    }

    @Test
    void aMatchOnlyOnADeletedAccountIsBlocked_andCreatesNothing() throws Exception {
        String email = uniqueEmail("gmail.com");
        account(email, UserStatus.DELETED);
        googleSignsIn(identity("sub-" + UUID.randomUUID(), email));

        assertThat(callback().getResponse().getRedirectedUrl())
                .isEqualTo(APP + "/problems?login=failed&reason=USER_BLOCKED");
        assertThat(accountsWithEmail(email)).hasSize(1);
    }

    /** A Google account that signed up, whose Google email later changed. */
    private User googleAccount(String sub, String email, UserStatus status) {
        return userRepository.save(User.builder().username(email).name("G").email(email).googleId(sub)
                .status(status.getValue()).roles(new HashSet<>()).build());
    }

    @Test
    void aLinkedUserWhoseGoogleEmailChangedSignsInToTheSameAccount_andNoRowIsCreated() throws Exception {
        String sub = "sub-" + UUID.randomUUID();
        String oldEmail = uniqueEmail("gmail.com");
        String newEmail = uniqueEmail("gmail.com");
        User account = googleAccount(sub, oldEmail, UserStatus.ACTIVE);
        long accounts = userRepository.count();
        googleSignsIn(identity(sub, newEmail));

        assertSignedIn(callback());
        assertThat(userRepository.count()).isEqualTo(accounts);
        assertThat(accountsWithEmail(newEmail)).isEmpty();
        assertThat(userRepository.findById(account.getId()).orElseThrow().getEmail()).isEqualTo(oldEmail);
    }

    /** V6 lets a soft-deleted account keep the Google id of a live one: the live one signs in. */
    @Test
    void aLiveAndADeletedAccountWithTheGoogleId_signInToTheLiveOne() throws Exception {
        String sub = "sub-" + UUID.randomUUID();
        googleAccount(sub, uniqueEmail("gmail.com"), UserStatus.DELETED);
        User live = googleAccount(sub, uniqueEmail("gmail.com"), UserStatus.ACTIVE);
        googleSignsIn(identity(sub, uniqueEmail("gmail.com")));

        assertSignedIn(callback());
        assertThat(userRepository.findById(live.getId()).orElseThrow().getLastLogin()).isNotNull();
    }

    @Test
    void aGoogleIdThatOnlyADeletedAccountHas_isBlocked_andCreatesNothing() throws Exception {
        String sub = "sub-" + UUID.randomUUID();
        googleAccount(sub, uniqueEmail("gmail.com"), UserStatus.DELETED);
        long accounts = userRepository.count();
        googleSignsIn(identity(sub, uniqueEmail("gmail.com")));

        assertThat(callback().getResponse().getRedirectedUrl())
                .isEqualTo(APP + "/problems?login=failed&reason=USER_BLOCKED");
        assertThat(userRepository.count()).isEqualTo(accounts);
    }
}
