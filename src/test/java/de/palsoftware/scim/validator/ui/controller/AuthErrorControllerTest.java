package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.security.AuthErrorReason;
import org.junit.jupiter.api.Test;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;

class AuthErrorControllerTest {

    private final AuthErrorController controller = new AuthErrorController();

    @Test
    void authError_mapsAllKnownReasonsAndIgnoresUntrustedInput() {
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
    }
}
