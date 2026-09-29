package vn.thanhtuanle.security.dto;

import lombok.Builder;
import lombok.Data;
import vn.thanhtuanle.common.enums.BanType;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class BanResponse {
    private UUID id;
    private BanType type;
    private String value;
    private String reason;
    private LocalDateTime expiresAt;
    private String createdBy;
    private LocalDateTime createdAt;
}
