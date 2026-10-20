package vn.thanhtuanle.user;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import vn.thanhtuanle.auth.AuthCookies;
import vn.thanhtuanle.config.SecurityConfig;
import vn.thanhtuanle.oj.common.security.OjJwtAuthenticationFilter;
import vn.thanhtuanle.oj.common.web.error.ResourceNotFoundException;
import vn.thanhtuanle.oj.common.web.security.OjAccessDeniedHandler;
import vn.thanhtuanle.oj.common.web.security.OjAuthenticationEntryPoint;
import vn.thanhtuanle.common.exception.GlobalExceptionHandler;
import vn.thanhtuanle.user.dto.PublicProfileResponse;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = PublicProfileController.class)
@Import({SecurityConfig.class, OjJwtAuthenticationFilter.class, GlobalExceptionHandler.class,
        OjAuthenticationEntryPoint.class, OjAccessDeniedHandler.class, AuthCookies.class})
@ActiveProfiles("test")
class PublicProfileControllerTest {

    @Autowired MockMvc mockMvc;
    @MockBean UserService userService;
    @MockBean JwtDecoder jwtDecoder;
    @MockBean UserDetailsService userDetailsService;

    @Test
    void anonymousReadsAProfileWithoutPrivateFields() throws Exception {
        UUID id = UUID.randomUUID();
        when(userService.publicProfile("alice")).thenReturn(
                new PublicProfileResponse(id, "alice", "Alice", "a.png", LocalDateTime.of(2026, 1, 2, 3, 4)));

        mockMvc.perform(get("/api/v1/users/public/alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(id.toString()))
                .andExpect(jsonPath("$.data.username").value("alice"))
                .andExpect(jsonPath("$.data.name").value("Alice"))
                .andExpect(jsonPath("$.data.avatar").value("a.png"))
                .andExpect(jsonPath("$.data.createdAt").exists())
                .andExpect(jsonPath("$.data.email").doesNotExist())
                .andExpect(jsonPath("$.data.roles").doesNotExist())
                .andExpect(jsonPath("$.data.status").doesNotExist())
                .andExpect(jsonPath("$.data.googleId").doesNotExist());
    }

    @Test
    void unknownUserIs404() throws Exception {
        when(userService.publicProfile("nobody")).thenThrow(new ResourceNotFoundException("User not found"));

        mockMvc.perform(get("/api/v1/users/public/nobody"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found"));
    }

    @Test
    void batchReturnsTheFoundUsers() throws Exception {
        UUID a = UUID.randomUUID();
        UUID b = UUID.randomUUID();
        when(userService.publicProfiles(List.of(a, b))).thenReturn(List.of(
                new PublicProfileResponse(a, "alice", "Alice", null, LocalDateTime.of(2026, 1, 2, 3, 4))));

        mockMvc.perform(get("/api/v1/users/public").param("ids", a + "," + b))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].username").value("alice"))
                .andExpect(jsonPath("$.data[0].email").doesNotExist());
    }

    @Test
    void moreThan100IdsIs400() throws Exception {
        String ids = IntStream.range(0, 101).mapToObj(i -> UUID.randomUUID().toString())
                .collect(Collectors.joining(","));

        mockMvc.perform(get("/api/v1/users/public").param("ids", ids))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("At most 100 ids per request"));
        verifyNoInteractions(userService);
    }

    @Test
    void anEmptyIdListIs400WithItsOwnMessage() throws Exception {
        mockMvc.perform(get("/api/v1/users/public").param("ids", ""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("ids must not be empty"));
        verifyNoInteractions(userService);
    }

    @Test
    void badInputFromAnAnonymousCallerIsNotLoggedAtError() throws Exception {
        Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        root.addAppender(appender);
        try {
            String ids = IntStream.range(0, 101).mapToObj(i -> UUID.randomUUID().toString())
                    .collect(Collectors.joining(","));
            mockMvc.perform(get("/api/v1/users/public").param("ids", ids)).andExpect(status().isBadRequest());
            mockMvc.perform(get("/api/v1/users/public").param("ids", "")).andExpect(status().isBadRequest());
        } finally {
            root.detachAppender(appender);
        }
        assertThat(appender.list).noneMatch(e -> e.getLevel().isGreaterOrEqual(Level.ERROR));
    }
}
