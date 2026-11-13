package de.palsoftware.scim.validator.ui.security;

import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class SecurityConfigAndActuatorFilterTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void processOidcUser_verifiedEmail_provisionsUserAndGrantsAdminWhenConfigured() {
        MgmtUserService mgmtUserService = mock(MgmtUserService.class);
        SecurityConfig config = new SecurityConfig("scim-admin", "scim-user", "roles", mgmtUserService);

        OidcUser oidcUser = buildOidcUser(Map.of(
                "sub", "sub-admin",
                "email", "Admin@Example.com",
                "email_verified", true,
                "roles", List.of("scim-admin")
        ));

        OidcUser processed = config.processOidcUser(oidcUser);

        verify(mgmtUserService).provisionUser("admin@example.com");
        assertThat(processed.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ADMIN", "ROLE_USER");
    }

    @Test
    void processOidcUser_unverifiedOrMissingEmail_throwsOAuth2AuthenticationException() {
        MgmtUserService mgmtUserService = mock(MgmtUserService.class);
        SecurityConfig config = new SecurityConfig("scim-admin", "scim-user", "roles", mgmtUserService);

        OidcUser unverified = buildOidcUser(Map.of(
                "sub", "sub-unverified",
                "email", "victim@example.com",
                "email_verified", false
        ));
        OidcUser preferredUsernameOnly = buildOidcUser(Map.of(
                "sub", "sub-spoof",
                "preferred_username", "victim@example.com",
                "email_verified", true
        ));

        assertThatThrownBy(() -> config.processOidcUser(unverified))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThatThrownBy(() -> config.processOidcUser(preferredUsernameOnly))
                .isInstanceOf(OAuth2AuthenticationException.class);
        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void actuatorFilter_healthEndpointsAreAlwaysAllowedAndGrantRoleWhenValidKeyProvided() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("top-secret-actuator-key", 9090);

        // Public health check without API key succeeds
        MockHttpServletRequest reqNoKey = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        reqNoKey.setLocalPort(8080);
        MockHttpServletResponse resNoKey = new MockHttpServletResponse();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> chainCalled.set(true);

        filter.doFilter(reqNoKey, resNoKey, chain);

        assertThat(chainCalled).isTrue();
        assertThat(resNoKey.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        // Health check with valid API key attaches ROLE_ACTUATOR for show-components: when_authorized
        MockHttpServletRequest reqWithKey = new MockHttpServletRequest("GET", "/actuator/health");
        reqWithKey.setLocalPort(8080);
        reqWithKey.addHeader("X-API-Key", "top-secret-actuator-key");
        MockHttpServletResponse resWithKey = new MockHttpServletResponse();
        AtomicBoolean authObserved = new AtomicBoolean(false);

        filter.doFilter(reqWithKey, resWithKey, (req, res) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            authObserved.set(auth != null && auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ACTUATOR".equals(a.getAuthority())));
        });

        assertThat(authObserved).isTrue();
    }

    @Test
    void actuatorFilter_whenApiKeyConfigured_requiresMatchingConstantTimeHeaderOrBearer() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("expected-secret-key", 9090);

        // Missing key -> 401 even on management port
        MockHttpServletRequest missingReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        missingReq.setLocalPort(9090);
        MockHttpServletResponse missingRes = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean(false);
        filter.doFilter(missingReq, missingRes, (req, res) -> called.set(true));
        assertThat(called).isFalse();
        assertThat(missingRes.getStatus()).isEqualTo(401);

        // Wrong key -> 401
        MockHttpServletRequest wrongReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        wrongReq.addHeader("X-API-Key", "wrong-key");
        MockHttpServletResponse wrongRes = new MockHttpServletResponse();
        filter.doFilter(wrongReq, wrongRes, (req, res) -> called.set(true));
        assertThat(called).isFalse();
        assertThat(wrongRes.getStatus()).isEqualTo(401);

        // Matching Authorization: Bearer -> permitted with ROLE_ACTUATOR
        SecurityContextHolder.clearContext();
        MockHttpServletRequest bearerReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        bearerReq.addHeader("Authorization", "Bearer expected-secret-key");
        MockHttpServletResponse bearerRes = new MockHttpServletResponse();
        filter.doFilter(bearerReq, bearerRes, (req, res) -> called.set(true));
        assertThat(called).isTrue();
        assertThat(bearerRes.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void actuatorFilter_whenApiKeyBlank_allowsOnlyManagementPortAndBlocksPublicPort() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("", 9090);

        // Public application port 8080 -> 403 Forbidden
        MockHttpServletRequest publicPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        publicPortReq.setLocalPort(8080);
        MockHttpServletResponse publicPortRes = new MockHttpServletResponse();
        AtomicBoolean publicCalled = new AtomicBoolean(false);
        filter.doFilter(publicPortReq, publicPortRes, (req, res) -> publicCalled.set(true));
        assertThat(publicCalled).isFalse();
        assertThat(publicPortRes.getStatus()).isEqualTo(403);

        // Dedicated pod-internal management port 9090 -> permitted with ROLE_ACTUATOR
        MockHttpServletRequest mgmtPortReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        mgmtPortReq.setLocalPort(9090);
        MockHttpServletResponse mgmtPortRes = new MockHttpServletResponse();
        AtomicBoolean mgmtCalled = new AtomicBoolean(false);
        filter.doFilter(mgmtPortReq, mgmtPortRes, (req, res) -> mgmtCalled.set(true));
        assertThat(mgmtCalled).isTrue();
        assertThat(mgmtPortRes.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void actuatorFilter_blocksMatrixParamAndDotSegmentBypasses() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("secret-key", 9090);

        MockHttpServletRequest traversalReq = new MockHttpServletRequest("GET", "/actuator/health/..;/prometheus");
        traversalReq.setLocalPort(8080);
        MockHttpServletResponse traversalRes = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean(false);

        filter.doFilter(traversalReq, traversalRes, (req, res) -> called.set(true));

        assertThat(called).isFalse();
        assertThat(traversalRes.getStatus()).isEqualTo(400);

        MockHttpServletRequest matrixReq = new MockHttpServletRequest("GET", "/actuator/prometheus;v=1");
        matrixReq.setLocalPort(8080);
        MockHttpServletResponse matrixRes = new MockHttpServletResponse();
        filter.doFilter(matrixReq, matrixRes, (req, res) -> called.set(true));
        assertThat(called).isFalse();
        assertThat(matrixRes.getStatus()).isEqualTo(401);
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(3600), claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }
}
