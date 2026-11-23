package de.palsoftware.scim.validator.ui.controller;

import org.junit.jupiter.api.Test;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;

class AuthErrorControllerTest {

    private final AuthErrorController controller = new AuthErrorController();

    @Test
    void authError_mapsKnownReasonsAndIgnoresUntrustedInput() {
        assertReason("unverified_email", "Email verification required");
        assertReason("access_denied", "Sign-in was denied");
        assertReason("authorization_request_not_found", "Sign-in session expired");
        assertReason("invalid_token", "Account profile incomplete");
        assertReason(null, "Sign-in failed");
        assertReason("<script>alert(1)</script>", "Sign-in failed");
    }

    private void assertReason(String reason, String expectedTitle) {
        Model model = new ConcurrentModel();
        String view = controller.authError(reason, model);
        assertThat(view).isEqualTo("auth-error");
        assertThat(model.getAttribute("errorTitle")).isEqualTo(expectedTitle);
        assertThat((String) model.getAttribute("errorMessage"))
                .isNotBlank()
                .doesNotContain("<script>");
    }
}
