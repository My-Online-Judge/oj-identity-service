package vn.thanhtuanle.permission;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.thanhtuanle.entity.Permission;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {
    List<Permission> findByNameIn(Collection<String> names);
}
