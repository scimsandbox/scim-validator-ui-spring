package de.palsoftware.scim.validator.ui.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record PlaygroundExecuteRequest(
        @NotBlank(message = "Base URL is required")
        String baseUrl,
        String authToken,
        @NotBlank(message = "HTTP Method is required")
        String method,
        @NotBlank(message = "Endpoint path is required")
        String endpoint,
        Map<String, String> headers,
        String body
) {
}
