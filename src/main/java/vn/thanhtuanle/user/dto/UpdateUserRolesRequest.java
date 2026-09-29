package vn.thanhtuanle.user.dto;

import lombok.Data;

import java.util.Set;
import java.util.UUID;

@Data
public class UpdateUserRolesRequest {
    private Set<UUID> roleIds;
}
