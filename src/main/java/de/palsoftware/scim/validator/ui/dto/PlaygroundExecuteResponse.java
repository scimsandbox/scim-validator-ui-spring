package de.palsoftware.scim.validator.ui.dto;

import java.util.Map;

public record PlaygroundExecuteResponse(
        int statusCode,
        String statusText,
        long durationMs,
        String requestMethod,
        String requestUrl,
        Map<String, String> requestHeaders,
        String requestBody,
        Map<String, String> responseHeaders,
        String responseBody,
        String error
) {
    public static PlaygroundExecuteResponse error(String message, String method, String url, long durationMs) {
        return new PlaygroundExecuteResponse(
                0,
                "Error",
                durationMs,
                method,
                url,
                Map.of(),
                null,
                Map.of(),
                null,
                message
        );
    }
}
