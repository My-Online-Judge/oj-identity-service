package vn.thanhtuanle.user.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.dto.UserResponse;

import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "permissions", source = "roles", qualifiedByName = "rolesToPermissionNames")
    UserResponse toResponse(User user);

    @Named("rolesToPermissionNames")
    default Set<String> rolesToPermissionNames(Set<Role> roles) {
        if (roles == null) {
            return Set.of();
        }
        return roles.stream()
                .filter(role -> role.getPermissions() != null)
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toCollection(TreeSet::new));
    }
}
