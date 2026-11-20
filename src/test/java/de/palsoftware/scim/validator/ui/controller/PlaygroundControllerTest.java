package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.PlaygroundExecutionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlaygroundControllerTest {

    @Mock
    private PlaygroundExecutionService executionService;

    @Mock
    private MgmtUserService mgmtUserService;

    private PlaygroundController controller;
    private Model model;
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        controller = new PlaygroundController(executionService, mgmtUserService, "http://localhost:8080");
        model = new ExtendedModelMap();
        authentication = new TestingAuthenticationToken("user@example.com", "n/a");
    }

    @Test
    void playgroundRoot_redirectsToUsersTopic() {
        String view = controller.playgroundRoot();
        assertThat(view).isEqualTo("redirect:/playground/users");
    }

    @Test
    void playgroundTopic_validTopic_populatesModel() {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        String view = controller.playgroundTopic("groups", model, authentication);

        assertThat(view).isEqualTo("playground");
        assertThat(model.getAttribute("activeTopic")).isEqualTo("groups");
        assertThat(model.getAttribute("currentUser")).isEqualTo("Alex Morgan");
        assertThat(model.getAttribute("currentUserRole")).isEqualTo("User");
        assertThat(model.getAttribute("topics")).isNotNull();
    }

    @Test
    void playgroundTopic_invalidTopic_defaultsToUsers() {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        String view = controller.playgroundTopic("non-existent-topic", model, authentication);

        assertThat(view).isEqualTo("playground");
        assertThat(model.getAttribute("activeTopic")).isEqualTo("users");
    }

    @Test
    void playgroundTopic_nullOrUnverifiedAuthentication_handlesNullUserEmailGracefully() {
        String viewNullAuth = controller.playgroundTopic("users", model, null);
        assertThat(viewNullAuth).isEqualTo("playground");
        assertThat(model.getAttribute("currentUser")).isNull();
        assertThat(model.getAttribute("currentUserRole")).isEqualTo("User");

        java.time.Instant now = java.time.Instant.now();
        org.springframework.security.oauth2.core.oidc.OidcIdToken idToken =
                new org.springframework.security.oauth2.core.oidc.OidcIdToken(
                        "tok", now, now.plusSeconds(300),
                        Map.of("sub", "sub-1", "email", "u@example.com", "email_verified", false));
        Authentication unverifiedAuth = new TestingAuthenticationToken(
                new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(
                        java.util.Collections.emptyList(), idToken),
                "n/a");
        Model model2 = new ExtendedModelMap();
        String viewUnverified = controller.playgroundTopic("users", model2, unverifiedAuth);
        assertThat(viewUnverified).isEqualTo("playground");
        assertThat(model2.getAttribute("currentUser")).isNull();
        assertThat(model2.getAttribute("currentUserRole")).isEqualTo("User");
    }

    @Test
    void executeRequest_delegatesToService() {
        PlaygroundExecuteRequest request = new PlaygroundExecuteRequest(
                "http://localhost:8080/scim/v2",
                "sample-token",
                "GET",
                "/ServiceProviderConfig",
                Map.of(),
                null
        );

        PlaygroundExecuteResponse expectedResponse = new PlaygroundExecuteResponse(
                200,
                "OK",
                25L,
                "GET",
                "http://localhost:8080/scim/v2/ServiceProviderConfig",
                Map.of(),
                null,
                Map.of(),
                "{\"patch\":{\"supported\":true}}",
                null
        );

        when(executionService.execute(any(PlaygroundExecuteRequest.class))).thenReturn(expectedResponse);

        ResponseEntity<PlaygroundExecuteResponse> responseEntity = controller.executeRequest(request);

        assertThat(responseEntity.getStatusCode().value()).isEqualTo(200);
        assertThat(responseEntity.getBody()).isNotNull();
        assertThat(responseEntity.getBody().statusCode()).isEqualTo(200);
        assertThat(responseEntity.getBody().statusText()).isEqualTo("OK");
        assertThat(responseEntity.getBody().responseBody()).contains("patch");
    }
}
