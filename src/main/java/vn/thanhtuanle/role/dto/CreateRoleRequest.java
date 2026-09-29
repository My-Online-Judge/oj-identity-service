package vn.thanhtuanle.role.dto;

import lombok.Data;

@Data
public class CreateRoleRequest {
    // Validated in RoleService — the app has no Bean Validation provider on the
    // classpath, so annotations here would be no-ops.
    private String name;
    private String description;
}
