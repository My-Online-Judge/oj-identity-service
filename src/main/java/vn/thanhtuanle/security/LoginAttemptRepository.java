package vn.thanhtuanle.security;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import vn.thanhtuanle.entity.LoginAttempt;

import java.time.LocalDateTime;
import java.util.UUID;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, UUID>, JpaSpecificationExecutor<LoginAttempt> {
    long deleteByCreatedAtBefore(LocalDateTime cutoff);
}
