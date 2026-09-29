package vn.thanhtuanle.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import vn.thanhtuanle.common.enums.BanType;

import java.time.LocalDateTime;

@Entity
@Table(name = "t_access_bans")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class AccessBan extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private BanType type;

    @Column(nullable = false, length = 128)
    private String value;

    @Column(length = 255)
    private String reason;

    /** null = permanent. */
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
}
