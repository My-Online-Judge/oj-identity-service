package vn.thanhtuanle.user.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * What anyone may see of an account. Deliberately no email, roles, status or Google id, and no avatar: an avatar is a
 * third-party URL (Google's) that tells its host who reads the profile. {@code username} is null when the stored one
 * contains an '@' (none does since V8; kept as defence in depth).
 */
public record PublicProfileResponse(UUID id, String username, String name, LocalDateTime createdAt) {
}
