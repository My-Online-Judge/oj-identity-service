package vn.thanhtuanle.user;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import vn.thanhtuanle.common.constant.Routes;
import vn.thanhtuanle.oj.common.tls.PeerCertificates;
import vn.thanhtuanle.oj.common.web.error.ResourceNotFoundException;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;
import vn.thanhtuanle.user.dto.PublicProfileResponse;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Anonymous reads of public profiles ({@code /api/v1/users/public} is in the security white list). */
@Slf4j
@RestController
@RequiredArgsConstructor
public class PublicProfileController {

    static final int MAX_IDS = 100;
    /** mTLS peers that may look up an email-shaped username: submission-service's admin search resolves one. */
    private static final Set<String> INTERNAL_CLIENTS = Set.of("submission-service", "problem-service");
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final UserService userService;

    @Operation(summary = "Public profile by username (any case); unknown and deleted users are 404, and so is an"
            + " email-shaped username for anyone but an internal service")
    @GetMapping(Routes.USERS + "/public/{username}")
    public ApiResponse<PublicProfileResponse> byUsername(@PathVariable String username, HttpServletRequest request) {
        // Email is never public: answering an address would tell anyone whether it has an account.
        if (username.contains("@") && !fromInternalService(request)) {
            throw new ResourceNotFoundException("User not found");
        }
        return ApiResponse.success(userService.publicProfile(username));
    }

    @Operation(summary = "Public profiles by ids (1-100); unknown and deleted users are left out")
    @GetMapping(Routes.USERS + "/public")
    public ApiResponse<List<PublicProfileResponse>> byIds(@RequestParam List<UUID> ids) {
        if (ids.isEmpty()) {
            throw new BadIdsException("ids must not be empty");
        }
        if (ids.size() > MAX_IDS) {
            throw new BadIdsException("At most " + MAX_IDS + " ids per request");
        }
        return ApiResponse.success(userService.publicProfiles(ids));
    }

    /** Anonymous callers can send this at will, so it is a 400 logged at WARN without a stack, never at ERROR. */
    @ExceptionHandler(BadIdsException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiResponse<Object> handleBadIds(BadIdsException ex) {
        log.warn("Bad public-profile batch request: {}", ex.getMessage());
        return ApiResponse.error(HttpStatus.BAD_REQUEST.value(), ex.getMessage());
    }

    /**
     * Whether the mTLS peer certificate's CN is an internal service. Public traffic arrives through the api-gateway,
     * and a request without a client certificate counts as public.
     */
    private static boolean fromInternalService(HttpServletRequest request) {
        if (request.getAttribute(CERT_ATTRIBUTE) instanceof X509Certificate[] chain && chain.length > 0) {
            return PeerCertificates.commonName(chain[0]).filter(INTERNAL_CLIENTS::contains).isPresent();
        }
        return false;
    }

    static final class BadIdsException extends RuntimeException {
        BadIdsException(String message) {
            super(message);
        }
    }
}
