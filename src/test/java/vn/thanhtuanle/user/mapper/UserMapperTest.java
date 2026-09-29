package vn.thanhtuanle.user.mapper;

import org.junit.jupiter.api.Test;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.user.dto.UserResponse;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserMapperTest {

    private final UserMapper mapper = new UserMapperImpl();

    private Permission perm(String name) {
        Permission p = new Permission();
        p.setName(name);
        return p;
    }

    private Role role(String name, Permission... perms) {
        Role r = new Role();
        r.setName(name);
        r.setPermissions(Set.of(perms));
        return r;
    }

    @Test
    void flattensDistinctSortedPermissionNamesAcrossRoles() {
        User user = new User();
        user.setUsername("u@example.com");
        user.setRoles(Set.of(
                role("ADMIN", perm("problem:delete"), perm("problem:create")),
                role("EDITOR", perm("problem:create"))));

        UserResponse response = mapper.toResponse(user);

        assertEquals(List.of("problem:create", "problem:delete"),
                List.copyOf(response.getPermissions())); // sorted + distinct
    }

    @Test
    void emptyWhenRoleHasNoPermissions() {
        User user = new User();
        Role r = new Role();
        r.setName("USER");
        r.setPermissions(null);
        user.setRoles(Set.of(r));

        assertEquals(Set.of(), mapper.toResponse(user).getPermissions());
    }
}
