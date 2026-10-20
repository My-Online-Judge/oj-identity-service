package vn.thanhtuanle.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import vn.thanhtuanle.oj.common.web.payload.PageResponse;
import vn.thanhtuanle.oj.common.web.payload.PageSizes;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.security.dto.AttemptResponse;

import java.time.LocalDate;
import java.time.LocalDateTime;

/** Audit log of password/Google login attempts. Refresh-token calls are NOT logged (volume). */
@Service
@Slf4j
public class LoginAttemptService {

    static final int RETENTION_DAYS = 30;
    /** The length of {@code t_login_attempts.username}. The Google path records the email, up to 254 characters. */
    static final int USERNAME_MAX = 64;

    private final LoginAttemptRepository repository;
    private final TransactionTemplate audit;

    public LoginAttemptService(LoginAttemptRepository repository, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        // REQUIRES_NEW: a caller's transaction that is about to roll back must not take the audit row with it.
        this.audit = new TransactionTemplate(transactionManager);
        this.audit.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Never throws — the audit trail must not break login itself. The whole transaction runs inside the try: a failed
     * INSERT surfaces at flush or commit (a failed flush marks the transaction rollback-only, so its commit throws), and
     * getting the connection can fail too. With {@code @Transactional} on this method those happened in the proxy,
     * after the catch.
     */
    public void record(String username, ClientMeta meta, boolean success, String errorCode) {
        try {
            audit.executeWithoutResult(status -> repository.save(LoginAttempt.builder()
                    .username(truncate(username))
                    .ip(meta.ip())
                    .deviceHash(meta.deviceHash())
                    .userAgent(meta.userAgent())
                    .success(success)
                    .errorCode(errorCode)
                    .build()));
        } catch (Exception e) {
            log.warn("Failed to record login attempt for {}: {}", truncate(username), e.getMessage());
        }
    }

    private static String truncate(String username) {
        return username == null || username.length() <= USERNAME_MAX ? username : username.substring(0, USERNAME_MAX);
    }

    public PageResponse<AttemptResponse> list(int page, int size, String ip, String username,
                                              Boolean success, LocalDate createdFrom, LocalDate createdTo) {
        Page<AttemptResponse> dtoPage = repository
                .findAll(LoginAttemptSpecifications.filter(ip, username, success, createdFrom, createdTo),
                        PageRequest.of(page, PageSizes.cap(size), Sort.by("createdAt").descending()))
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
