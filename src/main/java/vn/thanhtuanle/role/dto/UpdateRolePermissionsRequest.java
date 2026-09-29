package vn.thanhtuanle.role.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Set;

@Data
public class UpdateRolePermissionsRequest {

    /** The full replacement set of permission names for the role (empty clears them). */
    @NotNull
    private Set<String> permissions;
}
