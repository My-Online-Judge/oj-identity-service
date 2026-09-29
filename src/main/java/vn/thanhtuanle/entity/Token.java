package vn.thanhtuanle.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import vn.thanhtuanle.common.enums.TokenType;

@Entity
@Table(name = "t_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class Token extends BaseEntity {

    @Column(unique = true, columnDefinition = "TEXT")
    private String token;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private TokenType tokenType = TokenType.ACCESS;

    private boolean revoked;
    private boolean expired;

    @Column(length = 45)
    private String ip;

    @Column(name = "device_hash", length = 128)
    private String deviceHash;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
}
