package vn.thanhtuanle.user;

import io.swagger.v3.oas.annotations.Operation;
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
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;
import vn.thanhtuanle.user.dto.PublicProfileResponse;

import java.util.List;
import java.util.UUID;

/** Anonymous reads of public profiles ({@code /api/v1/users/public} is in the security white list). */
@Slf4j
@RestController
@RequiredArgsConstructor
public class PublicProfileController {

    static final int MAX_IDS = 100;

    private final UserService userService;

    @Operation(summary = "Public profile by username (any case); unknown and deleted users are 404")
    @GetMapping(Routes.USERS + "/public/{username}")
    public ApiResponse<PublicProfileResponse> byUsername(@PathVariable String username) {
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

    static final class BadIdsException extends RuntimeException {
        BadIdsException(String message) {
            super(message);
        }
    }
}
