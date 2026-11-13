package de.palsoftware.scim.validator.ui.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BaseUrlTest {

    @Test
    void trimsAndStripsTrailingSlashes() {
        assertThat(BaseUrl.require("app.test", " https://website.example.test// ")).isEqualTo("https://website.example.test");
    }

    @Test
    void keepsPortAndPathSegmentsAndLeavesCleanValuesUntouched() {
        assertThat(BaseUrl.require("app.test", "https://example.test/base")).isEqualTo("https://example.test/base");
        assertThat(BaseUrl.require("app.test", "http://localhost:8099")).isEqualTo("http://localhost:8099");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", " / ", "https://", " https:// ", "https:", "scimsandbox.net", "//scimsandbox.net",
            "ftp://scimsandbox.net", "javascript:alert(1)", "https://sci msandbox.net"})
    void rejectsMissingBlankAndNonHttpUrls(String bad) {
        assertThatThrownBy(() -> BaseUrl.require("app.test", bad))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("app.test")
                .hasMessageContaining("absolute http(s) URL");
    }
}
