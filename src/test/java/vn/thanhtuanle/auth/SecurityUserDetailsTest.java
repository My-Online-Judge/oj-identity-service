package vn.thanhtuanle.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import vn.thanhtuanle.entity.Permission;
import vn.thanhtuanle.entity.Role;
import vn.thanhtuanle.entity.User;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityUserDetailsTest {

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

    private Set<String> authoritiesOf(User user) {
        return new SecurityUserDetails(user).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    @Test
    void includesRoleNameAndFlattenedPermissions() {
        User user = new User();
        user.setRoles(Set.of(role("ADMIN", perm("problem:create"), perm("problem:delete"))));

        Set<String> authorities = authoritiesOf(user);

        assertTrue(authorities.contains("ADMIN"));
        assertTrue(authorities.contains("problem:create"));
        assertTrue(authorities.contains("problem:delete"));
        assertEquals(3, authorities.size());
    }

    @Test
    void deduplicatesPermissionNameSharedAcrossRoles() {
        User user = new User();
        user.setRoles(Set.of(
                role("ADMIN", perm("problem:create")),
                role("EDITOR", perm("problem:create"))));

        long createCount = new SecurityUserDetails(user).getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter("problem:create"::equals)
                .count();

        assertEquals(1, createCount);
    }

    @Test
    void handlesRoleWithNullPermissions() {
        User user = new User();
        Role userRole = new Role();
        userRole.setName("USER");
        userRole.setPermissions(null);
        user.setRoles(Set.of(userRole));

        assertEquals(Set.of("USER"), authoritiesOf(user));
    }
}
