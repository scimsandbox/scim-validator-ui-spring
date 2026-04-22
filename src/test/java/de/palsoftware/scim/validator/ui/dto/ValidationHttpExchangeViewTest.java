package de.palsoftware.scim.validator.ui.dto;

import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class ValidationHttpExchangeViewTest {

    @Test
    void from_prettyPrintsJsonBodies() {
        ValidationHttpExchange exchange = new ValidationHttpExchange();
        exchange.setSequenceNumber(1);
        exchange.setMethod("POST");
        exchange.setUrl("https://example.test/scim/v2/Users");
        exchange.setRequestBody("{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"tester@example.com\"}");
        exchange.setResponseStatus(201);
        exchange.setResponseBody("{\"id\":\"123\",\"active\":true}");
        exchange.setCreatedAt(OffsetDateTime.parse("2026-03-24T12:00:00Z"));

        ValidationHttpExchangeView view = ValidationHttpExchangeView.from(exchange);

        assertThat(view.requestBody()).isEqualTo("""
                {
                  "schemas" : [ "urn:ietf:params:scim:schemas:core:2.0:User" ],
                  "userName" : "tester@example.com"
                }""");
        assertThat(view.responseBody()).isEqualTo("""
                {
                  "id" : "123",
                  "active" : true
                }""");
    }

    @Test
    void from_leavesNonJsonBodiesUnchanged() {
        ValidationHttpExchange exchange = new ValidationHttpExchange();
        exchange.setSequenceNumber(1);
        exchange.setMethod("GET");
        exchange.setUrl("https://example.test/scim/v2/Users/123");
        exchange.setRequestBody("plain request body");
        exchange.setResponseStatus(500);
        exchange.setResponseBody("not-json");
        exchange.setCreatedAt(OffsetDateTime.parse("2026-03-24T12:00:00Z"));

        ValidationHttpExchangeView view = ValidationHttpExchangeView.from(exchange);

        assertThat(view.requestBody()).isEqualTo("plain request body");
        assertThat(view.responseBody()).isEqualTo("not-json");
    }
}