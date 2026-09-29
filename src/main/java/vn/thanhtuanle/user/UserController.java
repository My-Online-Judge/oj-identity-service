package vn.thanhtuanle.user;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.user.dto.CreateUserRequest;
import vn.thanhtuanle.user.dto.ResetPasswordRequest;
import vn.thanhtuanle.user.dto.UpdateUserRequest;
import vn.thanhtuanle.user.dto.UpdateUserRolesRequest;
import vn.thanhtuanle.user.dto.UpdateUserStatusRequest;
import vn.thanhtuanle.user.dto.UserResponse;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "List users with filters (admin)")
    @GetMapping(Routes.USERS)
    @PreAuthorize("hasAuthority('user:read')")
    public ApiResponse<List<UserResponse>> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) Integer status,
            @RequestParam(required = false) UUID roleId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate createdFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate createdTo) {
        return ApiResponse.success(userService.list(page, size, search, status, roleId, createdFrom, createdTo));
    }

    @Operation(summary = "Get a user by id (admin)")
    @GetMapping(Routes.USERS + "/{id}")
    @PreAuthorize("hasAuthority('user:read')")
    public ApiResponse<UserResponse> get(@PathVariable UUID id) {
        return ApiResponse.success(userService.getById(id));
    }

    @Operation(summary = "Create a user (admin)")
    @PostMapping(Routes.USERS)
    @PreAuthorize("hasAuthority('user:create')")
    public ApiResponse<UserResponse> create(@RequestBody CreateUserRequest request) {
        return ApiResponse.created(userService.create(request));
    }

    @Operation(summary = "Update a user's profile (admin)")
    @PutMapping(Routes.USERS + "/{id}")
    @PreAuthorize("hasAuthority('user:update')")
    public ApiResponse<UserResponse> update(@PathVariable UUID id, @RequestBody UpdateUserRequest request) {
        return ApiResponse.success(userService.update(id, request));
    }

    @Operation(summary = "Enable/disable a user (admin)")
    @PatchMapping(Routes.USERS + "/{id}/status")
    @PreAuthorize("hasAuthority('user:update')")
    public ApiResponse<UserResponse> updateStatus(@PathVariable UUID id, @RequestBody UpdateUserStatusRequest request) {
        return ApiResponse.success(userService.updateStatus(id, request.getStatus()));
    }

    @Operation(summary = "Replace a user's roles (admin)")
    @PutMapping(Routes.USERS + "/{id}/roles")
    @PreAuthorize("hasAuthority('user:update')")
    public ApiResponse<UserResponse> updateRoles(@PathVariable UUID id, @RequestBody UpdateUserRolesRequest request) {
        return ApiResponse.success(userService.updateRoles(id, request.getRoleIds()));
    }

    @Operation(summary = "Reset a user's password (admin)")
    @PostMapping(Routes.USERS + "/{id}/reset-password")
    @PreAuthorize("hasAuthority('user:update')")
    public ApiResponse<Void> resetPassword(@PathVariable UUID id, @RequestBody ResetPasswordRequest request) {
        userService.resetPassword(id, request.getNewPassword());
        return ApiResponse.success();
    }

    @Operation(summary = "Soft-delete a user (admin)")
    @DeleteMapping(Routes.USERS + "/{id}")
    @PreAuthorize("hasAuthority('user:delete')")
    public ApiResponse<Void> delete(@PathVariable UUID id) {
        userService.softDelete(id);
        return ApiResponse.success();
    }
}
