package vn.thanhtuanle.auth;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import vn.thanhtuanle.oj.common.security.OjJwtDecoders;

import java.util.Optional;
import java.util.UUID;

/**
 * Who sent the request: the {@code uid} claim of its verified access token, never its {@code sub} (the username). V6
 * lets a new live account take the username of a soft-deleted one, so a still-valid token of the deleted account (its
 * revocation write may have failed) must not act as the new account. Every access token identity mints carries
 * {@code uid}, and oj-common's decoder leaves a request without one anonymous, so there is no fallback to {@code sub}.
 */
public final class Caller {

    private Caller() {
    }

    /** The user id of the request's verified access token; empty for a request without one. */
    public static Optional<UUID> id() {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken token) {
            String uid = token.getToken().getClaimAsString(OjJwtDecoders.UID_CLAIM);
            try {
                return uid == null ? Optional.empty() : Optional.of(UUID.fromString(uid));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }
}
