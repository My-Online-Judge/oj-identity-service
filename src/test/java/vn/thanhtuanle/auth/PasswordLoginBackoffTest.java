package vn.thanhtuanle.auth;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import vn.thanhtuanle.common.enums.CommonStatus;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.common.util.Sleeper;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.security.LoginRateLimiter;
import vn.thanhtuanle.user.UserRepository;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A credential spray must not stall identity: the backoff after a wrong password (2–8 s) is slept with no transaction
 * open and no pooled database connection held, so concurrent failing logins cannot drain the connection pool.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordLoginBackoffTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;
    @Autowired DataSource dataSource;

    @MockitoBean LoginRateLimiter loginRateLimiter;
    @MockitoBean Sleeper sleeper;

    @Test
    void aWrongPasswordSleepsTheBackoffOutsideAnyTransaction() throws Exception {
        String username = "spray_" + UUID.randomUUID().toString().substring(0, 8);
        userRepository.save(User.builder()
                .username(username)
                .name(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode("Secret123"))
                .status(CommonStatus.ACTIVE.getValue())
                .roles(new HashSet<>())
                .build());
        when(loginRateLimiter.recordFailure(eq(username), any(ClientMeta.class))).thenReturn(Duration.ofSeconds(2));
        AtomicReference<Boolean> transactionWhileSleeping = new AtomicReference<>();
        AtomicInteger connectionsWhileSleeping = new AtomicInteger(-1);
        doAnswer(invocation -> {
            transactionWhileSleeping.set(TransactionSynchronizationManager.isActualTransactionActive());
            connectionsWhileSleeping.set(((HikariDataSource) dataSource).getHikariPoolMXBean().getActiveConnections());
            return null;
        }).when(sleeper).sleep(any());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"Wrong1234\"}"))
                .andExpect(status().isUnauthorized());

        verify(sleeper).sleep(Duration.ofSeconds(2));
        assertThat(transactionWhileSleeping.get()).isFalse();
        assertThat(connectionsWhileSleeping.get()).as("pooled connections in use while sleeping").isZero();
    }
}
