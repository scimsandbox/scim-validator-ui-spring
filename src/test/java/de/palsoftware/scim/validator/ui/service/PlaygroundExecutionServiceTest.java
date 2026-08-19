package de.palsoftware.scim.validator.ui.service;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class PlaygroundExecutionServiceTest {

    private static HttpServer testServer;
    private static int serverPort;
    private static final AtomicReference<String> lastReceivedAuthHeader = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedBody = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedMethod = new AtomicReference<>();

    private final PlaygroundExecutionService service = new PlaygroundExecutionService();

    @BeforeAll
    static void startServer() throws IOException {
        testServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverPort = testServer.getAddress().getPort();

        testServer.createContext("/scim/v2/ServiceProviderConfig", exchange -> {
            lastReceivedMethod.set(exchange.getRequestMethod());
            lastReceivedAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            String response = "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig\"],\"patch\":{\"supported\":true}}";
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        testServer.createContext("/scim/v2/Users", exchange -> {
            lastReceivedMethod.set(exchange.getRequestMethod());
            lastReceivedAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            try (InputStream is = exchange.getRequestBody()) {
                lastReceivedBody.set(new String(is.readAllBytes(), StandardCharsets.UTF_8));
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                String response = "{\"id\":\"u-12345\",\"userName\":\"alex.morgan\",\"active\":true}";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
                exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + serverPort + "/scim/v2/Users/u-12345");
                exchange.sendResponseHeaders(201, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                String response = "{\"totalResults\":1,\"Resources\":[{\"id\":\"u-12345\",\"userName\":\"alex.morgan\"}]}";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        });

        testServer.createContext("/scim/v2/huge", exchange -> {
            byte[] bytes = new byte[4 * 1024 * 1024];
            java.util.Arrays.fill(bytes, (byte) 'x');
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        testServer.createContext("/scim/v2/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://169.254.169.254/latest/meta-data/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        testServer.start();
    }

    @AfterAll
    static void stopServer() {
        if (testServer != null) {
            testServer.stop(0);
        }
    }

    @Test
    void execute_getServiceProviderConfig_successful() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                "secret-token-123",
                "GET",
                "/ServiceProviderConfig",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.statusText()).isEqualTo("OK");
        assertThat(res.durationMs()).isGreaterThanOrEqualTo(0);
        assertThat(res.responseBody()).contains("ServiceProviderConfig");
        assertThat(lastReceivedAuthHeader.get()).isEqualTo("Bearer secret-token-123");
        assertThat(lastReceivedMethod.get()).isEqualTo("GET");
    }

    @Test
    void execute_postCreateUser_successfulWithFormattedJson() {
        String userPayload = "{\"userName\":\"alex.morgan\",\"active\":true}";
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2/",
                "secret-token-123",
                "POST",
                "/Users",
                Map.of("X-Custom-Trace", "trace-abc"),
                userPayload
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(201);
        assertThat(res.statusText()).isEqualTo("Created");
        assertThat(res.responseBody()).contains("u-12345");
        assertThat(res.responseHeaders().keySet().stream().anyMatch(h -> h.equalsIgnoreCase("location"))).isTrue();
        assertThat(lastReceivedBody.get()).isEqualTo(userPayload);
        assertThat(lastReceivedMethod.get()).isEqualTo("POST");
    }

    @Test
    void execute_connectionRefused_returnsCleanErrorResponse() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:1",
                null,
                "GET",
                "/Users",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).isNotNull();
        assertThat(res.error()).containsIgnoringCase("Connection");
    }

    @Test
    void execute_plainHttpNonLocalhost_isRejected() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://169.254.169.254",
                null,
                "GET",
                "/latest/meta-data/",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).contains("only allowed for localhost");
    }

    @Test
    void execute_httpsNonLocalhost_isAllowedThroughValidation() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "https://scim.invalid",
                null,
                "GET",
                "/Users",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        // Validation passes; the request fails later at connect time, not at the scheme gate.
        assertThat(res.error()).isNotNull();
        assertThat(res.error()).doesNotContain("only allowed for localhost");
    }

    @Test
    void execute_nonHttpScheme_isRejected() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "ftp://example.com",
                null,
                "GET",
                "/Users",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).contains("only http and https");
    }

    @Test
    void execute_redirectIsNotFollowed() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/redirect",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(302);
        assertThat(res.responseHeaders().keySet().stream().anyMatch(h -> h.equalsIgnoreCase("location"))).isTrue();
    }

    @Test
    void execute_tokenWithIllegalHeaderCharacter_isNeverEchoedOrLogged() {
        String secret = "SUPERSECRET-abcdef123456\u200b";
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                secret,
                "GET",
                "/ServiceProviderConfig",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).isNotNull();
        assertThat(res.error()).doesNotContain("SUPERSECRET");
        assertThat(res.error()).doesNotContain(secret);
        assertThat(res.error()).contains("***");
    }

    @Test
    void execute_oversizedResponse_isCappedRatherThanBuffered() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/huge",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).isNotNull();
    }

    @Test
    void execute_credentialFromHeadersMap_isNeverEchoedOrLogged() {
        String secret = "Basic BASICSECRET-dXNlcjpwYXNz\u200b";
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/ServiceProviderConfig",
                Map.of("Authorization", secret),
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.error()).isNotNull();
        assertThat(res.error()).doesNotContain("BASICSECRET");
        assertThat(res.error()).contains("***");
    }

    @Test
    void execute_shortAndNonBearerCredentials_areMaskedInEchoedHeaders() {
        PlaygroundExecuteRequest shortToken = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2", "abc", "GET", "/ServiceProviderConfig", null, null);
        PlaygroundExecuteResponse shortRes = service.execute(shortToken);
        assertThat(shortRes.requestHeaders().get("Authorization")).isEqualTo("Bearer ***");
        assertThat(shortRes.requestHeaders().get("Authorization")).doesNotContain("abc");

        PlaygroundExecuteRequest basic = new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2", null, "GET", "/ServiceProviderConfig",
                Map.of("Authorization", "Basic dXNlcjpzdXBlcnNlY3JldA=="), null);
        PlaygroundExecuteResponse basicRes = service.execute(basic);
        assertThat(basicRes.requestHeaders().get("Authorization")).startsWith("Basic ");
        assertThat(basicRes.requestHeaders().get("Authorization")).doesNotContain("c3VwZXJzZWNyZXQ");
        assertThat(basicRes.requestHeaders().get("Authorization")).contains("...");
    }

    @Test
    void execute_invalidUrl_returnsCleanErrorResponse() {
        PlaygroundExecuteRequest req = new PlaygroundExecuteRequest(
                "invalid url format :::",
                null,
                "GET",
                "/Users",
                null,
                null
        );

        PlaygroundExecuteResponse res = service.execute(req);

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).contains("Invalid URL");
    }
}
