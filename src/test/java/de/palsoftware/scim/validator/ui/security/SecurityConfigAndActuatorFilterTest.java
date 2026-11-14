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
    void processOidcUser_verifiedAndEnterpriseOmittedEmailVerified_provisionNormalizedEmail() {
        MgmtUserService mgmtUserService = mock(MgmtUserService.class);
        SecurityConfig config = new SecurityConfig("scim-admin", "scim-user", "roles", mgmtUserService);

        OidcUser oidcUser = buildOidcUser(Map.of(
                "sub", "sub-admin",
                "email", "Admin@Example.com",
                "email_verified", true,
                "preferred_username", "different@example.com",
                "roles", List.of("scim-admin")
        ));

        OidcUser processed = config.processOidcUser(oidcUser);

        verify(mgmtUserService).provisionUser("admin@example.com");
        assertThat(processed.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ADMIN", "ROLE_USER");

        // Enterprise/Entra ID user with omitted email_verified and UPN fallback
        OidcUser entraUser = buildOidcUser(Map.of(
                "sub", "sub-entra",
                "upn", "Entra.User@Contoso.com"
        ));
        config.processOidcUser(entraUser);
        verify(mgmtUserService).provisionUser("entra.user@contoso.com");
    }

    @Test
    void processOidcUser_explicitlyUnverifiedOrMissingValidEmail_throwsExpectedOAuth2Errors() {
        MgmtUserService mgmtUserService = mock(MgmtUserService.class);
        SecurityConfig config = new SecurityConfig("scim-admin", "scim-user", "roles", mgmtUserService);

        OidcUser unverifiedBool = buildOidcUser(Map.of(
                "sub", "sub-unverified-bool",
                "email", "victim@example.com",
                "upn", "victim@contoso.com",
                "email_verified", false
        ));
        OidcUser unverifiedStr = buildOidcUser(Map.of(
                "sub", "sub-unverified-str",
                "preferred_username", "victim@example.com",
                "email_verified", "false"
        ));
        OidcUser noValidEmailClaim = buildOidcUser(Map.of(
                "sub", "sub-no-email",
                "preferred_username", "plain-username-without-at",
                "email_verified", true
        ));

        assertThatThrownBy(() -> config.processOidcUser(unverifiedBool))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("unverified_email"));
        assertThatThrownBy(() -> config.processOidcUser(unverifiedStr))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("unverified_email"));
        assertThatThrownBy(() -> config.processOidcUser(noValidEmailClaim))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .isEqualTo("invalid_token"));
        verifyNoInteractions(mgmtUserService);
    }

    @Test
    void actuatorFilter_healthEndpointsAreAlwaysAllowedAndGrantRoleForValidKeyOrDedicatedManagementPort() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("top-secret-actuator-key", 9090, 8080);

        // Public health check without API key succeeds without ROLE_ACTUATOR
        MockHttpServletRequest reqNoKey = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        reqNoKey.setLocalPort(8080);
        MockHttpServletResponse resNoKey = new MockHttpServletResponse();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> chainCalled.set(true);

        filter.doFilter(reqNoKey, resNoKey, chain);

        assertThat(chainCalled).isTrue();
        assertThat(resNoKey.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        // Health check with valid X-Actuator-Api-Key attaches ROLE_ACTUATOR
        MockHttpServletRequest reqWithKey = new MockHttpServletRequest("GET", "/actuator/health");
        reqWithKey.setLocalPort(8080);
        reqWithKey.addHeader("X-Actuator-Api-Key", "top-secret-actuator-key");
        MockHttpServletResponse resWithKey = new MockHttpServletResponse();
        AtomicBoolean authObserved = new AtomicBoolean(false);

        filter.doFilter(reqWithKey, resWithKey, (req, res) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            authObserved.set(auth != null && auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ACTUATOR".equals(a.getAuthority())));
        });

        assertThat(authObserved).isTrue();

        // When no API key is configured, /actuator/health on dedicated management port grants ROLE_ACTUATOR
        SecurityContextHolder.clearContext();
        ActuatorApiKeyAuthFilter keylessFilter = new ActuatorApiKeyAuthFilter("", 9090, 8080);
        MockHttpServletRequest mgmtHealthReq = new MockHttpServletRequest("GET", "/actuator/health");
        mgmtHealthReq.setLocalPort(9090);
        AtomicBoolean mgmtHealthAuthObserved = new AtomicBoolean(false);
        keylessFilter.doFilter(mgmtHealthReq, new MockHttpServletResponse(), (req, res) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            mgmtHealthAuthObserved.set(auth != null && auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ACTUATOR".equals(a.getAuthority())));
        });
        assertThat(mgmtHealthAuthObserved).isTrue();
    }

    @Test
    void actuatorFilter_whenApiKeyConfigured_acceptsXActuatorApiKeyXApiKeyAndBearer() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("expected-secret-key", 9090, 8080);

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

        // Matching X-Actuator-Api-Key -> permitted with ROLE_ACTUATOR
        SecurityContextHolder.clearContext();
        MockHttpServletRequest xActuatorKeyReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        xActuatorKeyReq.addHeader("X-Actuator-Api-Key", "expected-secret-key");
        MockHttpServletResponse xActuatorKeyRes = new MockHttpServletResponse();
        filter.doFilter(xActuatorKeyReq, xActuatorKeyRes, (req, res) -> called.set(true));
        assertThat(called).isTrue();
        assertThat(xActuatorKeyRes.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        // Matching X-API-Key -> permitted
        called.set(false);
        SecurityContextHolder.clearContext();
        MockHttpServletRequest xApiKeyReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        xApiKeyReq.addHeader("X-Actuator-Api-Key", "   ");
        xApiKeyReq.addHeader("X-API-Key", "expected-secret-key");
        MockHttpServletResponse xApiKeyRes = new MockHttpServletResponse();
        filter.doFilter(xApiKeyReq, xApiKeyRes, (req, res) -> called.set(true));
        assertThat(called).isTrue();
        assertThat(xApiKeyRes.getStatus()).isEqualTo(200);

        // Matching Authorization: Bearer -> permitted with ROLE_ACTUATOR
        called.set(false);
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
    void actuatorFilter_whenApiKeyBlank_allowsOnlyDedicatedManagementPortAndRejectsSameServerPort() throws Exception {
        ActuatorApiKeyAuthFilter filter = new ActuatorApiKeyAuthFilter("", 9090, 8080);

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

        // Misconfigured managementPort == serverPort (8080 == 8080) -> NOT trusted as dedicated management port!
        SecurityContextHolder.clearContext();
        ActuatorApiKeyAuthFilter sharedPortFilter = new ActuatorApiKeyAuthFilter("", 8080, 8080);
        MockHttpServletRequest sharedPromReq = new MockHttpServletRequest("GET", "/actuator/prometheus");
        sharedPromReq.setLocalPort(8080);
        MockHttpServletResponse sharedPromRes = new MockHttpServletResponse();
        AtomicBoolean sharedPromCalled = new AtomicBoolean(false);
        sharedPortFilter.doFilter(sharedPromReq, sharedPromRes, (req, res) -> sharedPromCalled.set(true));
        assertThat(sharedPromCalled).isFalse();
        assertThat(sharedPromRes.getStatus()).isEqualTo(403);

        MockHttpServletRequest sharedHealthReq = new MockHttpServletRequest("GET", "/actuator/health");
        sharedHealthReq.setLocalPort(8080);
        sharedPortFilter.doFilter(sharedHealthReq, new MockHttpServletResponse(), (req, res) -> {});
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
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

    @Test
    void actuatorFilter_additionalPathHeaderPortAndNullKeyBranches() throws Exception {
        ActuatorApiKeyAuthFilter nullKeyZeroPortFilter = new ActuatorApiKeyAuthFilter(null, 0);

        // Non-actuator normal path and root path pass straight through
        MockHttpServletRequest appReq = new MockHttpServletRequest("GET", "/runs");
        MockHttpServletResponse appRes = new MockHttpServletResponse();
        AtomicBoolean appCalled = new AtomicBoolean(false);
        nullKeyZeroPortFilter.doFilter(appReq, appRes, (req, res) -> appCalled.set(true));
        assertThat(appCalled).isTrue();

        // Empty requestURI with servletPath null -> "" -> "/" -> passes through
        MockHttpServletRequest emptyUriReq = new MockHttpServletRequest("GET", "");
        emptyUriReq.setServletPath(null);
        AtomicBoolean emptyCalled = new AtomicBoolean(false);
        nullKeyZeroPortFilter.doFilter(emptyUriReq, new MockHttpServletResponse(), (req, res) -> emptyCalled.set(true));
        assertThat(emptyCalled).isTrue();

        // Empty requestURI with servletPath "/actuator" and managementPort=0 -> 403
        MockHttpServletRequest servletPathActuatorReq = new MockHttpServletRequest("GET", "");
        servletPathActuatorReq.setServletPath("/actuator");
        servletPathActuatorReq.setLocalPort(0);
        MockHttpServletResponse servletPathRes = new MockHttpServletResponse();
        nullKeyZeroPortFilter.doFilter(servletPathActuatorReq, servletPathRes, (req, res) -> {});
        assertThat(servletPathRes.getStatus()).isEqualTo(403);

        // Context path stripping + health path when expectedKeyDigest is null
        MockHttpServletRequest ctxHealthReq = new MockHttpServletRequest("GET", "/validator-ui/actuator/health");
        ctxHealthReq.setContextPath("/validator-ui");
        AtomicBoolean ctxHealthCalled = new AtomicBoolean(false);
        nullKeyZeroPortFilter.doFilter(ctxHealthReq, new MockHttpServletResponse(), (req, res) -> ctxHealthCalled.set(true));
        assertThat(ctxHealthCalled).isTrue();

        // Non-actuator traversal path passes through to downstream Spring Security firewall/router
        MockHttpServletRequest nonActuatorTraversal = new MockHttpServletRequest("GET", "/api/../users");
        AtomicBoolean nonActuatorCalled = new AtomicBoolean(false);
        nullKeyZeroPortFilter.doFilter(nonActuatorTraversal, new MockHttpServletResponse(),
                (req, res) -> nonActuatorCalled.set(true));
        assertThat(nonActuatorCalled).isTrue();

        // Encoded slash (%2f), backslash, and single-dot segment on /actuator return 400
        for (String badActuatorUri : List.of("/actuator%2fprometheus", "/actuator\\prometheus", "/actuator/./prometheus")) {
            MockHttpServletRequest badReq = new MockHttpServletRequest("GET", badActuatorUri);
            MockHttpServletResponse badRes = new MockHttpServletResponse();
            nullKeyZeroPortFilter.doFilter(badReq, badRes, (req, res) -> {});
            assertThat(badRes.getStatus()).isEqualTo(400);
        }

        // Key-configured filter header edge cases: blank X-API-Key + valid Bearer, Basic auth, blank Bearer, invalid key on health
        ActuatorApiKeyAuthFilter keyFilter = new ActuatorApiKeyAuthFilter("my-key", 9090);

        MockHttpServletRequest blankXKeyValidBearer = new MockHttpServletRequest("GET", "/actuator");
        blankXKeyValidBearer.addHeader("X-API-Key", "   ");
        blankXKeyValidBearer.addHeader("Authorization", "Bearer my-key");
        MockHttpServletResponse okRes = new MockHttpServletResponse();
        keyFilter.doFilter(blankXKeyValidBearer, okRes, (req, res) -> {});
        assertThat(okRes.getStatus()).isEqualTo(200);

        MockHttpServletRequest basicAuthReq = new MockHttpServletRequest("GET", "/actuator/info");
        basicAuthReq.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        MockHttpServletResponse basicRes = new MockHttpServletResponse();
        keyFilter.doFilter(basicAuthReq, basicRes, (req, res) -> {});
        assertThat(basicRes.getStatus()).isEqualTo(401);

        MockHttpServletRequest blankBearerReq = new MockHttpServletRequest("GET", "/actuator/info");
        blankBearerReq.addHeader("Authorization", "Bearer    ");
        MockHttpServletResponse blankBearerRes = new MockHttpServletResponse();
        keyFilter.doFilter(blankBearerReq, blankBearerRes, (req, res) -> {});
        assertThat(blankBearerRes.getStatus()).isEqualTo(401);

        SecurityContextHolder.clearContext();
        MockHttpServletRequest healthInvalidKey = new MockHttpServletRequest("GET", "/actuator/health");
        healthInvalidKey.addHeader("X-API-Key", "wrong-key");
        keyFilter.doFilter(healthInvalidKey, new MockHttpServletResponse(), (req, res) -> {});
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void securityConfig_beanFactoryAndNullOidcUserBranches() {
        MgmtUserService mgmtUserService = mock(MgmtUserService.class);
        SecurityConfig config6Arg = new SecurityConfig("scim-admin", "scim-user", "roles", "k", 9090, mgmtUserService);
        SecurityConfig config7Arg = new SecurityConfig("scim-admin", "scim-user", "roles", "k", 9090, 8080, mgmtUserService);

        assertThat(config6Arg.actuatorApiKeyAuthFilter()).isNotNull();
        assertThat(config7Arg.actuatorApiKeyAuthFilter()).isNotNull();
        assertThat(config7Arg.oidcUserService()).isNotNull();
        assertThatThrownBy(() -> config7Arg.processOidcUser(null))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(3600), claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }
}
