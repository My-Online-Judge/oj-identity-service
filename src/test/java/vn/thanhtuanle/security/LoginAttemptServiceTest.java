package vn.thanhtuanle.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.LoginAttempt;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    private static final ClientMeta META = new ClientMeta("1.2.3.4", "dev-1", "probe/1.0");

    @Mock LoginAttemptRepository repository;
    @InjectMocks LoginAttemptService service;

    @Test
    void record_persistsAllFields() {
        service.record("alice", META, false, "USER_NOT_EXISTED");

        ArgumentCaptor<LoginAttempt> captor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(repository).save(captor.capture());
        LoginAttempt saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo("alice");
        assertThat(saved.getIp()).isEqualTo("1.2.3.4");
        assertThat(saved.getDeviceHash()).isEqualTo("dev-1");
        assertThat(saved.getUserAgent()).isEqualTo("probe/1.0");
        assertThat(saved.isSuccess()).isFalse();
        assertThat(saved.getErrorCode()).isEqualTo("USER_NOT_EXISTED");
    }

    @Test
    void record_neverThrows_evenWhenRepositoryFails() {
        when(repository.save(any())).thenThrow(new RuntimeException("db down"));
        assertThatCode(() -> service.record("alice", META, true, null)).doesNotThrowAnyException();
    }

    @Test
    void prune_deletesRowsOlderThan30Days() {
        when(repository.deleteByCreatedAtBefore(any())).thenReturn(7L);
        service.prune();
        ArgumentCaptor<LocalDateTime> captor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(repository).deleteByCreatedAtBefore(captor.capture());
        assertThat(captor.getValue()).isBefore(LocalDateTime.now().minusDays(29));
    }
}
