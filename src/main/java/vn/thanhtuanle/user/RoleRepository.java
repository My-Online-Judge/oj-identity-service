package vn.thanhtuanle.user;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.thanhtuanle.entity.Role;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByName(String name);
}
