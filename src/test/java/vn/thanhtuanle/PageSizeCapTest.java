package vn.thanhtuanle;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import vn.thanhtuanle.entity.AccessBan;
import vn.thanhtuanle.entity.LoginAttempt;
import vn.thanhtuanle.entity.User;
import vn.thanhtuanle.security.AccessBanRepository;
import vn.thanhtuanle.security.AccessBanService;
import vn.thanhtuanle.security.LoginAttemptRepository;
import vn.thanhtuanle.security.LoginAttemptService;
import vn.thanhtuanle.user.UserRepository;
import vn.thanhtuanle.user.UserService;
import vn.thanhtuanle.user.mapper.UserMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A client cannot ask for an unbounded page: {@code size} is clamped to 100, never a 400. */
@ExtendWith(MockitoExtension.class)
class PageSizeCapTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserMapper userMapper;
    @Mock
    private LoginAttemptRepository loginAttemptRepository;
    @Mock
    private AccessBanRepository accessBanRepository;

    @InjectMocks
    private UserService userService;
    @InjectMocks
    private LoginAttemptService loginAttemptService;
    @InjectMocks
    private AccessBanService accessBanService;

    @Test
    @SuppressWarnings("unchecked")
    void users() {
        when(userRepository.findAll(any(Specification.class), any(Pageable.class))).thenReturn(Page.<User>empty());

        userService.list(0, 500, null, null, null, null, null);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).findAll(any(Specification.class), pageable.capture());
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
    }

    @Test
    @SuppressWarnings("unchecked")
    void loginAttempts() {
        when(loginAttemptRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(Page.<LoginAttempt>empty());

        loginAttemptService.list(0, 500, null, null, null, null, null);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(loginAttemptRepository).findAll(any(Specification.class), pageable.capture());
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
    }

    @Test
    void bans() {
        when(accessBanRepository.findAll(any(Pageable.class))).thenReturn(Page.<AccessBan>empty());

        accessBanService.list(0, 500);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(accessBanRepository).findAll(pageable.capture());
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
    }
}
