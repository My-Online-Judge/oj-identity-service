package vn.thanhtuanle.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.common.payload.ApiResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.security.dto.AttemptResponse;
import vn.thanhtuanle.security.dto.BanResponse;
import vn.thanhtuanle.security.dto.CreateBanRequest;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping(Routes.SECURITY)
@RequiredArgsConstructor
public class SecurityController {

    private final LoginAttemptService loginAttemptService;
    private final AccessBanService accessBanService;

    @GetMapping("/attempts")
    @PreAuthorize("hasAuthority('ban:read')")
    public ApiResponse<List<AttemptResponse>> listAttempts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) Boolean success,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate createdFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate createdTo) {
        return ApiResponse.success(loginAttemptService.list(page, size, ip, username, success, createdFrom, createdTo));
    }

    @GetMapping("/bans")
    @PreAuthorize("hasAuthority('ban:read')")
    public ApiResponse<List<BanResponse>> listBans(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ApiResponse.success(accessBanService.list(page, size));
    }

    @PostMapping("/bans")
    @PreAuthorize("hasAuthority('ban:create')")
    public ApiResponse<BanResponse> createBan(@RequestBody CreateBanRequest request,
                                              HttpServletRequest httpRequest) {
        return ApiResponse.success(accessBanService.create(request, ClientMeta.from(httpRequest)));
    }

    @DeleteMapping("/bans/{id}")
    @PreAuthorize("hasAuthority('ban:delete')")
    public ApiResponse<Void> deleteBan(@PathVariable UUID id) {
        accessBanService.delete(id);
        return ApiResponse.success();
    }
}
