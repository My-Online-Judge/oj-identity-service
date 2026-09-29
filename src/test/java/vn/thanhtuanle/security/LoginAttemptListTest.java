package vn.thanhtuanle.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import vn.thanhtuanle.common.payload.PageResponse;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.security.dto.AttemptResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAttemptListTest {

    @Mock LoginAttemptRepository repository;
    @InjectMocks LoginAttemptService service;

    @Test
    @SuppressWarnings("unchecked")
    void list_mapsEntitiesToDtos_withPagination() {
        LoginAttempt attempt = LoginAttempt.builder()
                .username("alice").ip("1.2.3.4").deviceHash("dev-1").success(false).errorCode("USER_NOT_EXISTED")
                .build();
        Page<LoginAttempt> page = new PageImpl<>(List.of(attempt), PageRequest.of(0, 20), 1);
        when(repository.findAll(any(Specification.class), any(Pageable.class))).thenReturn(page);

        PageResponse<AttemptResponse> result = service.list(0, 20, null, null, null, null, null);

        assertThat(result.getData()).hasSize(1);
        assertThat(result.getData().get(0).getUsername()).isEqualTo("alice");
        assertThat(result.getData().get(0).isSuccess()).isFalse();
    }
}
