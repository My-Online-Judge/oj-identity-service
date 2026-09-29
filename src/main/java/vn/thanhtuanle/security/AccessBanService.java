package vn.thanhtuanle.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.thanhtuanle.common.enums.BanType;
import vn.thanhtuanle.common.exception.AppException;
import vn.thanhtuanle.common.exception.ErrorCode;
import vn.thanhtuanle.common.payload.PageResponse;
import vn.thanhtuanle.common.util.ClientMeta;
import vn.thanhtuanle.entity.AccessBan;
import vn.thanhtuanle.security.dto.BanResponse;
import vn.thanhtuanle.security.dto.CreateBanRequest;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccessBanService {

    private final AccessBanRepository repository;
    private final AccessBanMirror mirror;

    public BanResponse create(CreateBanRequest request, ClientMeta caller) {
        BanType type = parseType(request.getType());
        String value = request.getValue() == null ? "" : request.getValue().trim();
        if (value.isBlank() || value.length() > 128) {
            throw new AppException(ErrorCode.BAN_INVALID);
        }
        // Guardrail: don't let an admin saw off the branch they're sitting on.
        if ((type == BanType.IP && value.equals(caller.ip()))
                || (type == BanType.DEVICE && value.equals(caller.deviceHash()))) {
            throw new AppException(ErrorCode.BAN_SELF);
        }
        if (repository.existsByTypeAndValue(type, value)) {
            throw new AppException(ErrorCode.BAN_EXISTED);
        }
        LocalDateTime expiresAt = request.getDurationHours() == null ? null
                : LocalDateTime.now().plusHours(request.getDurationHours());
        AccessBan ban = repository.save(AccessBan.builder()
                .type(type).value(value).reason(request.getReason()).expiresAt(expiresAt)
                .build());
        mirror.add(ban);
        log.info("Banned {} {} until {}", type, value, expiresAt == null ? "forever" : expiresAt);
        return toResponse(ban);
    }

    public PageResponse<BanResponse> list(int page, int size) {
        Page<BanResponse> dtoPage = repository
                .findAll(PageRequest.of(page, size, Sort.by("createdAt").descending()))
                .map(AccessBanService::toResponse);
        return PageResponse.of(dtoPage);
    }

    public void delete(UUID id) {
        AccessBan ban = repository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.BAN_NOT_FOUND));
        repository.delete(ban);
        mirror.remove(ban.getType(), ban.getValue());
        log.info("Unbanned {} {}", ban.getType(), ban.getValue());
    }

    /** Boot-time rebuild so the mirror survives Redis restarts/flushes. */
    @EventListener(ApplicationReadyEvent.class)
    public void rebuildMirror() {
        try {
            repository.findAll().forEach(mirror::add); // add() skips already-expired bans
            log.info("Access-ban mirror rebuilt ({} bans in DB)", repository.count());
        } catch (Exception e) {
            log.warn("Could not rebuild ban mirror: {}", e.getMessage());
        }
    }

    /** Nightly sweep of expired ban rows (mirror keys already self-evicted via TTL). */
    @Scheduled(cron = "0 40 3 * * *")
    @Transactional
    public void pruneExpired() {
        long removed = repository.deleteByExpiresAtBefore(LocalDateTime.now());
        if (removed > 0) {
            log.info("Pruned {} expired bans", removed);
        }
    }

    private static BanType parseType(String raw) {
        try {
            return BanType.valueOf(raw == null ? "" : raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new AppException(ErrorCode.BAN_INVALID);
        }
    }

    static BanResponse toResponse(AccessBan ban) {
        return BanResponse.builder()
                .id(ban.getId()).type(ban.getType()).value(ban.getValue())
                .reason(ban.getReason()).expiresAt(ban.getExpiresAt())
                .createdBy(ban.getCreatedBy()).createdAt(ban.getCreatedAt())
                .build();
    }
}
