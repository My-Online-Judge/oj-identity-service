package vn.thanhtuanle.role;

import org.junit.jupiter.api.Test;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.role.dto.RoleResponse;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RoleMapperTest {

    private final RoleMapper mapper = new RoleMapperImpl();

    private Permission perm(String name) {
        Permission p = new Permission();
        p.setName(name);
        return p;
    }

    @Test
    void mapsRoleWithSortedPermissionNames() {
        Role role = new Role();
        role.setName("ADMIN");
        role.setDescription("Admin role");
        role.setPermissions(Set.of(perm("problem:delete"), perm("problem:create")));

        RoleResponse response = mapper.toResponse(role);

        assertEquals("ADMIN", response.getName());
        assertEquals(List.of("problem:create", "problem:delete"),
                List.copyOf(response.getPermissions()));
    }

    @Test
    void emptyPermissionsWhenNull() {
        Role role = new Role();
        role.setName("USER");
        role.setPermissions(null);

        assertEquals(Set.of(), mapper.toResponse(role).getPermissions());
    }
}
