package de.palsoftware.scim.validator.ui.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.UUID;

public record ValidationHttpExchangeView(
        UUID id,
        int sequenceNumber,
        String method,
        String url,
        String requestHeaders,
        String requestBody,
        Integer responseStatus,
        String responseHeaders,
        String responseBody,
        OffsetDateTime createdAt) {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public String getDisplayUrl() {
        if (url == null || url.isBlank()) {
            return url;
        }
        try {
            return URLDecoder.decode(url, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return url;
        }
    }

    public static ValidationHttpExchangeView from(ValidationHttpExchange exchange) {
        return new ValidationHttpExchangeView(
                exchange.getId(),
                exchange.getSequenceNumber(),
                exchange.getMethod(),
                exchange.getUrl(),
                exchange.getRequestHeaders(),
                formatJsonBody(exchange.getRequestBody()),
                exchange.getResponseStatus(),
                exchange.getResponseHeaders(),
                formatJsonBody(exchange.getResponseBody()),
                exchange.getCreatedAt());
    }

    private static String formatJsonBody(String body) {
        if (body == null || body.isBlank()) {
            return body;
        }

        try {
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(OBJECT_MAPPER.readTree(body));
        } catch (JsonProcessingException ex) {
            return body;
        }
    }
}
