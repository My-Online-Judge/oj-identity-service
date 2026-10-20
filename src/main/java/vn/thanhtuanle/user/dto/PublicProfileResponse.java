package vn.thanhtuanle.user.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/** What anyone may see of an account. Deliberately no email, roles, status or Google id. */
public record PublicProfileResponse(UUID id, String username, String name, String avatar, LocalDateTime createdAt) {
}
