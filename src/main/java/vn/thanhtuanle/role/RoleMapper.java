package vn.thanhtuanle.role;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.role.dto.RoleResponse;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface RoleMapper {

    @Mapping(target = "permissions", source = "permissions", qualifiedByName = "permissionsToNames")
    RoleResponse toResponse(Role role);

    List<RoleResponse> toResponses(List<Role> roles);

    @Named("permissionsToNames")
    default Set<String> permissionsToNames(Set<Permission> permissions) {
        if (permissions == null) {
            return Set.of();
        }
        return permissions.stream()
                .map(Permission::getName)
                .collect(Collectors.toCollection(TreeSet::new));
    }
}
