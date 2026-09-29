package vn.thanhtuanle.security.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class AttemptResponse {
    private UUID id;
    private String username;
    private String ip;
    private String deviceHash;
    private String userAgent;
    private boolean success;
    private String errorCode;
    private LocalDateTime createdAt;
}
