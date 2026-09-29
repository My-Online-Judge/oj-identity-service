package vn.thanhtuanle.permission;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import vn.thanhtuanle.permission.dto.PermissionResponse;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final PermissionMapper permissionMapper;

    public List<PermissionResponse> listPermissions() {
        return permissionMapper.toResponses(permissionRepository.findAll(Sort.by("name")));
    }
}
