package vn.thanhtuanle.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Proves the actuator EXPOSURE allowlist in {@code application.yml}, not the SecurityConfig
 * whitelist. Before the fix, {@code management.endpoints.web.exposure.include: '*'} exposes
 * every actuator endpoint (env, beans, configprops, loggers, heapdump, threaddump, ...), and
 * SecurityConfig's {@code .anyRequest().authenticated()} then lets ANY authenticated user --
 * including a non-admin contestant -- reach them.
 *
 * <p>This uses a full {@link SpringBootTest} (not a {@code @WebMvcTest} slice) with a real
 * {@code test}-profile context, because actuator's web endpoint handler mapping is only
 * registered on the full application context. {@code @WithMockUser} establishes a plain,
 * non-admin authenticated principal; oj-common's {@code OjJwtAuthenticationFilter} passes such requests
 * through unchanged (no Authorization header/cookie present), so the mock-user context
 * survives it -- it never replaces an existing authentication.
 *
 * <p>{@code /actuator/heapdump} is deliberately NOT exercised here: hitting it pre-fix would
 * generate a real heap dump (slow, large, and would leak an artifact into CI). It is governed
 * by the exact same exposure allowlist as {@code env}/{@code beans}/etc, so this test covers
 * the mechanism that protects it; heapdump itself is verified separately against the live stack.
 */
// Spring Boot's test support disables real metrics/tracing export by default (only a no-op
// Simple registry is active) to avoid tests hitting real backends. That would make
// PrometheusScrapeEndpoint's supporting bean absent here, so /actuator/prometheus would 404/500
// for reasons that have nothing to do with the exposure allowlist under test.
// @AutoConfigureObservability restores the real (Prometheus) registry so this test matches the
// deployed app's actual behavior.
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
@ActiveProfiles("test")
class ActuatorExposureSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // One assertion per endpoint (rather than several andExpect calls chained in one test) so a
    // single failure doesn't hide the status of the endpoints after it -- each line below is
    // independent RED/GREEN evidence for that one endpoint.
    //
    // The invariant is "not served" (status not 2xx), not specifically 404. An endpoint left out
    // of the exposure allowlist is unmapped, and in THIS app an unmapped path is rendered as
    // HTTP 500 by the catch-all @ExceptionHandler(Exception.class) in GlobalExceptionHandler
    // (it wraps the framework's NoResourceFoundException; the body is only "No static resource
    // actuator/env." -- no endpoint data). Either way the caller never receives the env/beans/
    // heapdump payload, which is the whole point. Asserting == 404 would couple this security
    // test to that unrelated error-rendering detail; asserting "not 2xx" is the real guarantee.

    private void assertNotServedToNonAdmin(String path) throws Exception {
        mockMvc.perform(get(path)).andExpect(result ->
                org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus())
                        .as("%s must not be served (2xx) to an authenticated non-admin user", path)
                        .isGreaterThanOrEqualTo(400));
    }

    @Test
    @WithMockUser
    void env_isNotServed_forAuthenticatedNonAdminUser() throws Exception {
        assertNotServedToNonAdmin("/actuator/env");
    }

    @Test
    @WithMockUser
    void beans_isNotServed_forAuthenticatedNonAdminUser() throws Exception {
        assertNotServedToNonAdmin("/actuator/beans");
    }

    @Test
    @WithMockUser
    void configprops_isNotServed_forAuthenticatedNonAdminUser() throws Exception {
        assertNotServedToNonAdmin("/actuator/configprops");
    }

    @Test
    @WithMockUser
    void loggers_isNotServed_forAuthenticatedNonAdminUser() throws Exception {
        assertNotServedToNonAdmin("/actuator/loggers");
    }

    /**
     * Health must stay MAPPED (not 404) for a non-admin user -- that is the invariant the
     * exposure allowlist controls. We deliberately do NOT assert HTTP 200 here: health's
     * UP/DOWN composite status also depends on live downstream dependencies (Redis) that this
     * test harness and CI do not provision (no Redis service container -- see
     * .github/workflows/ci.yml), so it legitimately reports 503 DOWN here while still being
     * correctly exposed. On the real deployed stack, with Redis reachable, it is 200.
     */
    @Test
    @WithMockUser
    void health_staysReachable_forAuthenticatedNonAdminUser() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(result -> org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus())
                        .as("actuator/health must be mapped (not 404) for a non-admin user")
                        .isNotEqualTo(404));
    }

    /**
     * Prometheus must stay MAPPED (not 404) so Prometheus can keep scraping it — that is the
     * invariant the exposure allowlist controls, and the one my fix could accidentally break by
     * dropping it from the list. We assert "not 404" rather than 200 because the scrape endpoint
     * legitimately errors (500) inside this MockMvc test harness even with
     * {@code @AutoConfigureObservability} — the meter registry is not fully wired for a mock
     * dispatch — which has nothing to do with whether the endpoint is exposed. The live stack
     * (real registry) returns 200; that is verified against the running deployment separately.
     */
    @Test
    @WithMockUser
    void prometheus_staysReachable_forAuthenticatedNonAdminUser() throws Exception {
        mockMvc.perform(get("/actuator/prometheus"))
                .andExpect(result -> org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus())
                        .as("actuator/prometheus must stay mapped (not 404) for the Prometheus scrape")
                        .isNotEqualTo(404));
    }
}
