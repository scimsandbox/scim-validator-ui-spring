package de.palsoftware.scim.validator.ui.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TargetUrlPolicyTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "https://scim.example.com/scim/v2",
            "https://scim.example.com:8443/scim/v2/Users",
            "HTTPS://SCIM.EXAMPLE.COM/scim/v2"
    })
    void httpsTargetsAreAllowedAnywhere(String url) {
        assertThat(TargetUrlPolicy.validate(url)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:8080/scim/v2",
            "http://127.0.0.1:8080/scim/v2",
            "http://LOCALHOST:8080/scim/v2",
            "http://[::1]:8080/scim/v2"
    })
    void plainHttpIsAllowedForLocalhost(String url) {
        assertThat(TargetUrlPolicy.validate(url)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.0.0.5/scim/v2",
            "http://scim.example.com/scim/v2"
    })
    void plainHttpIsRejectedForEverythingElse(String url) {
        assertThatThrownBy(() -> TargetUrlPolicy.validate(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("only allowed for localhost");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ftp://example.com/x", "file:///etc/passwd", "gopher://example.com"})
    void nonHttpSchemesAreRejected(String url) {
        assertThatThrownBy(() -> TargetUrlPolicy.validate(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("only http and https");
    }

    @Test
    void blankTargetIsRejected() {
        assertThatThrownBy(() -> TargetUrlPolicy.validate("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void targetWithoutHostIsRejected() {
        assertThatThrownBy(() -> TargetUrlPolicy.validate("https:///scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must include a host");
    }
}
