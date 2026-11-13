package de.palsoftware.scim.validator.ui.controller;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WebsiteUrlAdviceTest {

    @Test
    void exposesTheNormalizedWebsiteUrl() {
        assertThat(new WebsiteUrlAdvice("https://website.example.test/").websiteUrl())
                .isEqualTo("https://website.example.test");
    }

    @Test
    void failsFastOnMissingOrMalformedConfig() {
        assertThatThrownBy(() -> new WebsiteUrlAdvice(""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("APP_COMPLIANCE_PUBLIC_BASE_URL");
        assertThatThrownBy(() -> new WebsiteUrlAdvice("scimsandbox.net"))
                .isInstanceOf(IllegalStateException.class);
    }
}
