package de.palsoftware.scim.validator.ui.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BaseUrlTest {

    @Test
    void trimsAndStripsTrailingSlashes() {
        assertThat(BaseUrl.require("app.test", " https://website.example.test// ")).isEqualTo("https://website.example.test");
    }

    @Test
    void keepsPathSegmentsAndLeavesCleanValuesUntouched() {
        assertThat(BaseUrl.require("app.test", "https://example.test/base")).isEqualTo("https://example.test/base");
    }

    @Test
    void rejectsMissingBlankAndSlashOnlyValues() {
        for (String bad : new String[] {null, "", "   ", " / "}) {
            assertThatThrownBy(() -> BaseUrl.require("app.test", bad))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("app.test");
        }
    }
}
