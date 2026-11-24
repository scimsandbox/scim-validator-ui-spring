package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.security.AuthErrorReason;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;

class AuthErrorControllerTest {

    private final AuthErrorController controller = new AuthErrorController(
            new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("okta")
                    .clientId("client-id")
                    .clientSecret("client-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/okta")
                    .authorizationUri("https://okta.example.test/authorize")
                    .tokenUri("https://okta.example.test/token")
                    .build()));

    @Test
    void authError_mapsAllKnownReasonsIgnoresUntrustedInputAndUsesDerivedLoginPath() {
        for (AuthErrorReason reason : AuthErrorReason.values()) {
            assertReason(reason.code(), reason);
        }
        assertReason(null, AuthErrorReason.AUTHENTICATION_FAILED);
        assertReason("   ", AuthErrorReason.AUTHENTICATION_FAILED);
        assertReason("<script>alert(1)</script>", AuthErrorReason.AUTHENTICATION_FAILED);
    }

    private void assertReason(String reason, AuthErrorReason expected) {
        Model model = new ConcurrentModel();
        String view = controller.authError(reason, model);
        assertThat(view).isEqualTo("auth-error");
        assertThat(model.getAttribute("errorTitle")).isEqualTo(expected.title());
        assertThat(model.getAttribute("errorMessage")).isEqualTo(expected.message());
        assertThat(model.getAttribute("retryLoginPath")).isEqualTo("/oauth2/authorization/okta");
    }
}
