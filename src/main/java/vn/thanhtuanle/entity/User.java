package vn.thanhtuanle.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "t_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class User extends BaseEntity {
    private String username;
    private String name;
    private String password;
    private String email;
    private Integer status;
    private Boolean enabledMfa;
    private LocalDateTime lastLogin;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "last_login_device_hash", length = 128)
    private String lastLoginDeviceHash;

    @Column(name = "avatar")
    private String avatar;

    @Column(name = "google_id")
    private String googleId;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "t_users_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;
}