package vn.thanhtuanle.user.dto;

import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Data
public class CreateUserRequest {
    private String username;
    private String name;
    private String email;
    private String password;
    private Integer status;
    private Set<UUID> roleIds;
}
