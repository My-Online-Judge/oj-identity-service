package vn.thanhtuanle.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import vn.thanhtuanle.common.payload.PageResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.security.dto.AttemptResponse;

import java.time.LocalDate;
import java.time.LocalDateTime;

/** Audit log of password/Google login attempts. Refresh-token calls are NOT logged (volume). */
@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    static final int RETENTION_DAYS = 30;

    private final LoginAttemptRepository repository;

    /**
     * Never throws — the audit trail must not break login itself.
     *
     * <p>REQUIRES_NEW is load-bearing: failed logins are recorded from inside AuthService's
     * @Transactional method right before the AppException is rethrown, which marks that
     * transaction rollback-only. Without a fresh transaction the failure row would be
     * silently rolled back with it (observed live before this annotation existed).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String username, ClientMeta meta, boolean success, String errorCode) {
        try {
            repository.save(LoginAttempt.builder()
                    .username(username)
                    .ip(meta.ip())
                    .deviceHash(meta.deviceHash())
                    .userAgent(meta.userAgent())
                    .success(success)
                    .errorCode(errorCode)
                    .build());
        } catch (Exception e) {
            log.warn("Failed to record login attempt for {}: {}", username, e.getMessage());
        }
    }

    public PageResponse<AttemptResponse> list(int page, int size, String ip, String username,
                                              Boolean success, LocalDate createdFrom, LocalDate createdTo) {
        Page<AttemptResponse> dtoPage = repository
                .findAll(LoginAttemptSpecifications.filter(ip, username, success, createdFrom, createdTo),
                        PageRequest.of(page, size, Sort.by("createdAt").descending()))
                .map(a -> AttemptResponse.builder()
                        .id(a.getId()).username(a.getUsername()).ip(a.getIp())
                        .deviceHash(a.getDeviceHash()).userAgent(a.getUserAgent())
                        .success(a.isSuccess()).errorCode(a.getErrorCode())
                        .createdAt(a.getCreatedAt())
                        .build());
        return PageResponse.of(dtoPage);
    }

    /** Nightly retention sweep (03:30 VN time — the app pins Asia/Ho_Chi_Minh). */
    @Scheduled(cron = "0 30 3 * * *")
    @Transactional
    public void prune() {
        long removed = repository.deleteByCreatedAtBefore(LocalDateTime.now().minusDays(RETENTION_DAYS));
        if (removed > 0) {
            log.info("Pruned {} login attempts older than {} days", removed, RETENTION_DAYS);
        }
    }
}
