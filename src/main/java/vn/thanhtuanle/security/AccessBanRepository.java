package vn.thanhtuanle.security;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.thanhtuanle.common.enums.BanType;
import vn.thanhtuanle.entity.AccessBan;

import java.time.LocalDateTime;
import java.util.UUID;

public interface AccessBanRepository extends JpaRepository<AccessBan, UUID> {
    boolean existsByTypeAndValue(BanType type, String value);
    long deleteByExpiresAtBefore(LocalDateTime cutoff);
}
