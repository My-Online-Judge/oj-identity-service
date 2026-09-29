package vn.thanhtuanle.permission;

import org.mapstruct.Mapper;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.permission.dto.PermissionResponse;

import java.util.List;

@Mapper(componentModel = "spring")
public interface PermissionMapper {

    PermissionResponse toResponse(Permission permission);

    List<PermissionResponse> toResponses(List<Permission> permissions);
}
