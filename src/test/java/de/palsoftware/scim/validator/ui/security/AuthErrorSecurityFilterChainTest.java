package de.palsoftware.scim.validator.ui.security;

import de.palsoftware.scim.validator.ui.controller.AuthErrorController;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
                .andExpect(content().string(containsString("href=\"/css/error.css\"")))
                .andExpect(content().string(containsString("href=\"/oauth2/authorization/auth0?prompt=login\"")));

        mockMvc.perform(get("/auth-error").param("reason", "authorization_request_not_found").accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Sign-in session expired")))
                .andExpect(content().string(containsString("href=\"/oauth2/authorization/auth0\"")))
                .andExpect(content().string(not(containsString("prompt=login"))));
    }

    @Test
    void errorStylesheetIsPublic() throws Exception {
        mockMvc.perform(get("/css/error.css"))
                .andExpect(status().isOk());
    }

    @Test
    void loginCallbackWithoutSavedAuthorizationRequest_redirectsToAuthError() throws Exception {
        mockMvc.perform(get("/login/oauth2/code/auth0").param("code", "x").param("state", "y"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/auth-error?reason=authorization_request_not_found"));
    }

    @Test
    void oauth2AuthorizationRequest_includesPromptLoginOnlyWhenRequested() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/auth0").param("prompt", "login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("prompt=login")));

        mockMvc.perform(get("/oauth2/authorization/auth0"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("prompt="))));

        mockMvc.perform(get("/oauth2/authorization/auth0").param("prompt", "none"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", not(containsString("prompt="))));
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

    @ParameterizedTest
    @CsvSource({
            "400, Bad request, The request could not be understood.",
            "403, Access denied, You do not have permission to perform this action",
            "404, Page not found, The page you requested could not be found.",
            "405, Method not allowed, This action is not supported for the requested address.",
            "500, Something went wrong, An unexpected server error occurred."
    })
    void customErrorPageRendersStatusWithoutReflectingUntrustedDetails(
            int statusCode, String expectedTitle, String expectedMessageSnippet) throws Exception {
        mockMvc.perform(get("/error")
                        .accept(MediaType.TEXT_HTML)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, statusCode)
                        .requestAttr(RequestDispatcher.ERROR_MESSAGE, "<script>leaked-internal-detail</script>"))
                .andExpect(status().is(statusCode))
                .andExpect(content().string(containsString("<title>" + expectedTitle + " — SCIM Compliance</title>")))
                .andExpect(content().string(containsString("Error " + statusCode)))
                .andExpect(content().string(containsString(expectedTitle)))
                .andExpect(content().string(containsString(expectedMessageSnippet)))
                .andExpect(content().string(containsString("href=\"/\"")))
                .andExpect(content().string(not(containsString("Whitelabel Error Page"))))
                .andExpect(content().string(not(containsString("leaked-internal-detail"))));
    }

    @Test
    void directErrorPageVisitHides999StatusAndWhitelabel() throws Exception {
        mockMvc.perform(get("/error").accept(MediaType.TEXT_HTML))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("Something went wrong")))
                .andExpect(content().string(containsString("The request could not be completed.")))
                .andExpect(content().string(containsString("href=\"/\"")))
                .andExpect(content().string(not(containsString("999"))))
                .andExpect(content().string(not(containsString("Whitelabel Error Page"))));
    }

    @Test
    void errorEndpointPreservesJsonNegotiation() throws Exception {
        mockMvc.perform(get("/error")
                        .accept(MediaType.APPLICATION_JSON)
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 404))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(404));
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
