package vn.thanhtuanle.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Entity
@Table(name = "t_login_attempts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class LoginAttempt extends BaseEntity {

    @Column(length = 64)
    private String username;

    @Column(length = 45)
    private String ip;

    @Column(name = "device_hash", length = 128)
    private String deviceHash;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "error_code", length = 64)
    private String errorCode;
}
