package vn.thanhtuanle.security.dto;

import lombok.Data;

@Data
public class CreateBanRequest {
    private String type;          // "IP" | "DEVICE"
    private String value;
    private String reason;
    private Integer durationHours; // null = permanent
}
