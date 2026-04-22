package de.palsoftware.scim.validator.ui.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidationRunForm(
        @NotBlank(message = "Run name is required") String name,

        @NotBlank(message = "SCIM base URL is required") String baseUrl,

        @NotBlank(message = "Bearer token is required") String authToken) {
}
