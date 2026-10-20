package vn.thanhtuanle.common.exception;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import vn.thanhtuanle.oj.common.web.payload.ApiResponse;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;

class UniqueUserConstraintsTest {

    /** What Spring's translation makes of a unique violation on Postgres: Hibernate's exception, with the name. */
    private static DataIntegrityViolationException violationOf(String constraint) {
        SQLException sql = new SQLException("duplicate key value violates unique constraint", "23505");
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("could not execute statement", sql, constraint));
    }

    @Test
    void theUserIndexesMapToTheirConflicts() {
        assertThat(UniqueUserConstraints.toErrorCode(violationOf("ux_users_username_lower")))
                .contains(ErrorCode.USERNAME_EXISTED);
        assertThat(UniqueUserConstraints.toErrorCode(violationOf("ux_users_email_lower")))
                .contains(ErrorCode.EMAIL_EXISTED);
        assertThat(UniqueUserConstraints.toErrorCode(violationOf("ux_users_google_id")))
                .contains(ErrorCode.GOOGLE_ACCOUNT_EXISTED);
        assertThat(ErrorCode.USERNAME_EXISTED.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(ErrorCode.EMAIL_EXISTED.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(ErrorCode.GOOGLE_ACCOUNT_EXISTED.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void theirCodesAreConflicts_andNoOtherIs() {
        assertThat(ErrorCode.values()).filteredOn(UniqueUserConstraints::isConflict).containsExactlyInAnyOrder(
                ErrorCode.USERNAME_EXISTED, ErrorCode.EMAIL_EXISTED, ErrorCode.GOOGLE_ACCOUNT_EXISTED);
    }

    @Test
    void theNameIsFoundDeeperInTheCauseChain() {
        DataIntegrityViolationException wrapped = new DataIntegrityViolationException("outer",
                new RuntimeException("middle", violationOf("ux_users_email_lower").getCause()));

        assertThat(UniqueUserConstraints.toErrorCode(wrapped)).contains(ErrorCode.EMAIL_EXISTED);
    }

    @Test
    void anyOtherViolationIsNotOurs() {
        assertThat(UniqueUserConstraints.toErrorCode(violationOf("ukdjdnp60wf0lq8erni3suse1np"))).isEmpty();
        assertThat(UniqueUserConstraints.toErrorCode(violationOf(null))).isEmpty();
        assertThat(UniqueUserConstraints.toErrorCode(new DataIntegrityViolationException("no cause"))).isEmpty();
    }

    @Test
    void theHandlerAnswers409ForAUserIndex_and500ForAnythingElse() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();

        ResponseEntity<ApiResponse<Object>> conflict =
                handler.handleDataIntegrityViolation(violationOf("ux_users_username_lower"));
        assertThat(conflict.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(conflict.getBody().getMessage()).isEqualTo("Username already exists");

        ResponseEntity<ApiResponse<Object>> other =
                handler.handleDataIntegrityViolation(violationOf("ukdjdnp60wf0lq8erni3suse1np"));
        assertThat(other.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(other.getBody().getMessage()).isEqualTo("Internal server error");
    }
}
