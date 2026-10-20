package vn.thanhtuanle.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.auth.SessionRevoker;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.UserRepository;

import java.time.Duration;
import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The login audit never breaks a login (H2, which enforces the varchar lengths). Its insert runs in a transaction of its
 * own inside the try, so even a failure at flush or commit, which marks that transaction rollback-only, stays inside.
 * The failures are real ones: values longer than their columns.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LoginAttemptAuditTest {

    private static final ClientMeta META = new ClientMeta("10.0.0.9", "dev-1", "audit/1.0");

    @Autowired MockMvc mockMvc;
    @Autowired LoginAttemptService loginAttemptService;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @Autowired LoginAttemptRepository loginAttemptRepository;
    @MockitoBean LoginRateLimiter loginRateLimiter;
    @MockitoBean SessionRevoker sessionRevoker;
    @MockitoBean Sleeper sleeper;

    @Test
    void aSeventyCharacterUsernameIsAuditedTruncated() {
        // The Google path audits the email, up to 254 characters, into the varchar(64) column.
        String email = "a".repeat(58) + "@x.test" + "-tail";
        assertThat(email).hasSize(70);

        assertThatCode(() -> loginAttemptService.record(email, META, false, "GOOGLE_EMAIL_UNVERIFIED"))
                .doesNotThrowAnyException();

        assertThat(loginAttemptRepository.findAll())
                .extracting(LoginAttempt::getUsername)
                .contains(email.substring(0, 64));
    }

    @Test
    void anInsertThatFailsAtFlushNeverLeavesRecord() {
        // 70 characters into the varchar(64) error_code column: the INSERT fails at flush, inside the audit transaction.
        assertThatCode(() -> loginAttemptService.record("alice", META, false, "E".repeat(70)))
                .doesNotThrowAnyException();
    }

    @Test
    void aFailingAuditLeavesAWrongPasswordA401AndItsDelay() throws Exception {
        String username = "aud_" + UUID.randomUUID().toString().substring(0, 8);
        userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode("Secret123"))
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
        when(loginRateLimiter.recordFailure(any())).thenReturn(Duration.ofSeconds(2));
        // A client address longer than the audit's varchar(45) ip column: the audit INSERT fails at flush.
        mockMvc.perform(post("/api/v1/auth/login")
                        .with(request -> {
                            request.setRemoteAddr("f".repeat(60));
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"Wrong1234\"}"))
                .andExpect(status().isUnauthorized());

        verify(sleeper).sleep(Duration.ofSeconds(2));
    }
}
