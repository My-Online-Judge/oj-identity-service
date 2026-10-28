package vn.thanhtuanle.role.dto;

import lombok.Data;

@Data
public class CreateRoleRequest {
    // Validated by hand in RoleService, so a violation answers with the role's own error codes. (Bean Validation is
    // on the classpath: the controllers' @Valid bodies, LoginRequest for one, are checked by it.)
    private String name;
    private String description;
}
