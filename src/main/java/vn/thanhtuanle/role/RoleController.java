package vn.thanhtuanle.role;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.role.dto.CreateRoleRequest;
import vn.thanhtuanle.role.dto.RoleResponse;
import vn.thanhtuanle.role.dto.UpdateRolePermissionsRequest;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @Operation(summary = "List all roles with their permissions (admin)")
    @GetMapping(Routes.ROLES)
    @PreAuthorize("hasAuthority('role:read')")
    public ApiResponse<List<RoleResponse>> listRoles() {
        return ApiResponse.success(roleService.listRoles());
    }

    @Operation(summary = "Create a new role (admin)")
    @PostMapping(Routes.ROLES)
    @PreAuthorize("hasAuthority('role:create')")
    public ApiResponse<RoleResponse> createRole(@Valid @RequestBody CreateRoleRequest request) {
        return ApiResponse.created(roleService.create(request.getName(), request.getDescription()));
    }

    @Operation(summary = "Replace a role's permissions (admin)")
    @PutMapping(Routes.ROLES + "/{id}/permissions")
    @PreAuthorize("hasAuthority('role:update')")
    public ApiResponse<RoleResponse> updatePermissions(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateRolePermissionsRequest request) {
        return ApiResponse.success(roleService.updatePermissions(id, request.getPermissions()));
    }

    @Operation(summary = "Delete a role (admin)")
    @DeleteMapping(Routes.ROLES + "/{id}")
    @PreAuthorize("hasAuthority('role:delete')")
    public ApiResponse<Void> deleteRole(@PathVariable UUID id) {
        roleService.delete(id);
        return ApiResponse.success();
    }
}
