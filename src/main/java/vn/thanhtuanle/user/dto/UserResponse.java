package vn.thanhtuanle.user.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import vn.thanhtuanle.common.payload.BaseResponse;
import vn.thanhtuanle.entity.Role;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class UserResponse extends BaseResponse {
    private String username;
    private String name;
    private String email;
    private Integer status;
    private Boolean enabledMfa;
    private LocalDateTime lastLogin;
    private String avatar;
    private String googleId;
    private Set<Role> roles;
    private Set<String> permissions;
}
