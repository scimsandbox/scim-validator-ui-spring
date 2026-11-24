package de.palsoftware.scim.validator.ui.security;

import de.palsoftware.scim.validator.ui.controller.AuthErrorController;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AuthErrorController.class)
@Import({SecurityConfig.class, AuthErrorSecurityFilterChainTest.TestOAuth2Config.class})
@TestPropertySource(properties = {
        "app.compliance.public-base-url=https://website.example.test",
        "app.security.oidc.admin-role=admin",
        "app.security.oidc.user-role=user",
        "app.security.oidc.role-claim=https://scimplayground.dev/roles",
        "app.security.actuator.api-key=",
        "management.server.port=9090",
        "server.port=8080"
})
class AuthErrorSecurityFilterChainTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private MgmtUserService mgmtUserService;

    @Test
    void authErrorPageIsPublicAndDoesNotLoopToIdentityProvider() throws Exception {
        mockMvc.perform(get("/auth-error").param("reason", "access_denied").accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sign-in was denied")))
                .andExpect(content().string(containsString("href=\"/\"")))
                .andExpect(content().string(not(containsString("/oauth2/authorization/auth0"))));
    }

    @Test
    void authErrorPageSanitizesUntrustedReasonInput() throws Exception {
        mockMvc.perform(get("/auth-error").param("reason", "<script>alert(1)</script>").accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sign-in failed")))
                .andExpect(content().string(not(containsString("<script>"))));
    }

    @Test
    void unauthenticatedRootRequestRedirectsToIdentityProvider() throws Exception {
        mockMvc.perform(get("/").accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/oauth2/authorization/auth0"));
    }

    @TestConfiguration
    static class TestOAuth2Config {

        @Bean
        ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("auth0")
                    .clientId("test-client")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/auth0")
                    .scope("openid", "profile", "email")
                    .authorizationUri("https://test.auth0.com/authorize")
                    .tokenUri("https://test.auth0.com/oauth/token")
                    .jwkSetUri("https://test.auth0.com/.well-known/jwks.json")
                    .issuerUri("https://test.auth0.com/")
                    .userNameAttributeName("sub")
                    .build());
        }
    }
}
