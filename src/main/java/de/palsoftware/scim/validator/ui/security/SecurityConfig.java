package de.palsoftware.scim.validator.ui.security;

import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
    private static final int MAX_LOG_FIELD_LENGTH = 200;
    private static final String CSRF_COOKIE_NAME = "SCIM_VALIDATOR_UI_XSRF";
    public static final String AUTH_ERROR_PATH = "/auth-error";

    private final String adminRole;
    private final String userRole;
    private final String roleClaim;
    private final String actuatorApiKey;
    private final int managementPort;
    private final int serverPort;
    private final MgmtUserService mgmtUserService;

    public SecurityConfig(String adminRole,
                          String userRole,
                          String roleClaim,
                          MgmtUserService mgmtUserService) {
        this(adminRole, userRole, roleClaim, "", 9090, 8080, mgmtUserService);
    }

    public SecurityConfig(String adminRole,
                          String userRole,
                          String roleClaim,
                          String actuatorApiKey,
                          int managementPort,
                          MgmtUserService mgmtUserService) {
        this(adminRole, userRole, roleClaim, actuatorApiKey, managementPort, 8080, mgmtUserService);
    }

    @Autowired
    public SecurityConfig(@Value("${app.security.oidc.admin-role}") String adminRole,
                          @Value("${app.security.oidc.user-role}") String userRole,
                          @Value("${app.security.oidc.role-claim}") String roleClaim,
                          @Value("${app.security.actuator.api-key:}") String actuatorApiKey,
                          @Value("${management.server.port:9090}") int managementPort,
                          @Value("${server.port:8080}") int serverPort,
                          @Lazy MgmtUserService mgmtUserService) {
        this.adminRole = adminRole;
        this.userRole = userRole;
        this.roleClaim = roleClaim;
        this.actuatorApiKey = actuatorApiKey;
        this.managementPort = managementPort;
        this.serverPort = serverPort;
        this.mgmtUserService = mgmtUserService;
    }

    @Bean
    public ActuatorApiKeyAuthFilter actuatorApiKeyAuthFilter() {
        return new ActuatorApiKeyAuthFilter(actuatorApiKey, managementPort, serverPort);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   LogoutSuccessHandler oidcLogoutSuccessHandler,
                                                   ActuatorApiKeyAuthFilter actuatorApiKeyAuthFilter,
                                                   ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);

        http.addFilterBefore(actuatorApiKeyAuthFilter, LogoutFilter.class)
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/actuator", "/actuator/**").hasAuthority("ROLE_ACTUATOR")
                // favicon*.svg rather than an exact match: this app serves one badge per section
                // (favicon.svg for SCIM Compliance, favicon-playground.svg for SCIM Playground).
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon*.svg", "/favicon.ico", "/robots.txt", "/error", AUTH_ERROR_PATH).permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(auth -> auth.authorizationRequestResolver(
                    authorizationRequestResolver(clientRegistrationRepository)))
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
                .failureHandler(oauth2FailureHandler()))
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler))
            .csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository())
                .csrfTokenRequestHandler(requestHandler));

        return http.build();
    }

    public static String oidcLoginUrl(ClientRegistrationRepository clientRegistrationRepository) {
        List<String> registrationIds = new ArrayList<>();
        if (clientRegistrationRepository instanceof Iterable<?> registrations) {
            for (Object candidate : registrations) {
                if (candidate instanceof ClientRegistration registration
                        && AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
                    registrationIds.add(registration.getRegistrationId());
                }
            }
        }
        if (registrationIds.size() != 1) {
            throw new IllegalStateException("Expected exactly one authorization_code client registration, found "
                    + registrationIds + ". Multi-provider login needs a different authentication entry point.");
        }
        return OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                + "/" + registrationIds.getFirst();
    }

    OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return applyPromptLoginIfRequested(request, delegate.resolve(request));
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                return applyPromptLoginIfRequested(request, delegate.resolve(request, clientRegistrationId));
            }
        };
    }

    private static OAuth2AuthorizationRequest applyPromptLoginIfRequested(
            HttpServletRequest request,
            OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null || !"login".equals(request.getParameter("prompt"))) {
            return authorizationRequest;
        }
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(params -> params.put("prompt", "login"))
                .build();
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        return new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    }

    OidcUserService oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return new OidcUserService() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
                OidcUser oidcUser = delegate.loadUser(userRequest);
                return processOidcUser(oidcUser);
            }
        };
    }

    OidcUser processOidcUser(OidcUser oidcUser) {
        String email = AuthenticatedUser.resolveEmail(oidcUser);
        if (email == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(AuthErrorReason.MISSING_EMAIL.code(),
                            "A valid email claim is required for management access",
                            null));
        }

        Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());
        addMappedAuthorities(extractClaimValues(oidcUser.getClaim(roleClaim)), mappedAuthorities);
        mgmtUserService.provisionUser(email);

        return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    AuthenticationFailureHandler oauth2FailureHandler() {
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
        return (request, response, exception) -> {
            AuthErrorReason reason = AuthErrorReason.fromException(exception);
            if (exception instanceof OAuth2AuthenticationException oauth2Ex) {
                log.warn("OIDC login failed (oauth2ErrorCode={}, mappedReason={}): {}",
                        sanitizeForLog(oauth2Ex.getError().getErrorCode()),
                        reason.code(),
                        sanitizeForLog(oauth2Ex.getError().getDescription()));
            } else {
                log.warn("OIDC login failed (exception={}, mappedReason={}): {}",
                        exception.getClass().getSimpleName(),
                        reason.code(),
                        sanitizeForLog(exception.getMessage()));
            }
            redirectStrategy.sendRedirect(request, response, AUTH_ERROR_PATH + "?reason=" + reason.code());
        };
    }

    private static String sanitizeForLog(String value) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replaceAll("[\\p{Cc}\\u2028\\u2029]", " ");
        return cleaned.length() > MAX_LOG_FIELD_LENGTH
                ? cleaned.substring(0, MAX_LOG_FIELD_LENGTH) + "..."
                : cleaned;
    }

    @SuppressWarnings("java:S3330")
    private CookieCsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName(CSRF_COOKIE_NAME);
        return repository;
    }

    private void addMappedAuthorities(List<String> roles, Set<GrantedAuthority> mappedAuthorities) {
        String normalizedAdminRole = normalizeRole(adminRole);
        String normalizedUserRole = normalizeRole(userRole);
        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        if (roles == null) {
            return;
        }
        for (String role : roles) {
            String normalized = normalizeRole(role);
            if (normalized == null) {
                continue;
            }
            if (normalizedAdminRole != null && normalized.equals(normalizedAdminRole)) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            if (normalizedUserRole != null && normalized.equals(normalizedUserRole)) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            }
        }
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            return null;
        }
        String normalized = role.trim().toUpperCase(Locale.ROOT);
        if (normalized.startsWith("ROLE_")) {
            return normalized.substring("ROLE_".length());
        }
        return normalized;
    }

    private List<String> extractClaimValues(Object claimValue) {
        if (claimValue == null) {
            return List.of();
        }
        if (claimValue instanceof String value) {
            return List.of(value.split("[,\\s]+"));
        }
        if (claimValue instanceof Collection<?> collection) {
            List<String> values = new ArrayList<>();
            for (Object entry : collection) {
                if (entry != null) {
                    values.add(entry.toString());
                }
            }
            return values;
        }
        if (claimValue.getClass().isArray()) {
            int length = Array.getLength(claimValue);
            List<String> values = new ArrayList<>(length);
            for (int index = 0; index < length; index++) {
                Object entry = Array.get(claimValue, index);
                if (entry != null) {
                    values.add(entry.toString());
                }
            }
            return values;
        }
        return List.of(claimValue.toString());
    }
}
