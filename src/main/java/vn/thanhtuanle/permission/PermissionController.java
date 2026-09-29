package vn.thanhtuanle.permission;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.permission.dto.PermissionResponse;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @Operation(summary = "List all permissions (admin)")
    @GetMapping(Routes.PERMISSIONS)
    @PreAuthorize("hasAuthority('permission:read')")
    public ApiResponse<List<PermissionResponse>> listPermissions() {
        return ApiResponse.success(permissionService.listPermissions());
    }
}
