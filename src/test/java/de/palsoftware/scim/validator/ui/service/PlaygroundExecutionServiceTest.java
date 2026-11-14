package de.palsoftware.scim.validator.ui.service;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class PlaygroundExecutionServiceTest {

    private static HttpServer testServer;
    private static int serverPort;
    private static final AtomicReference<String> lastReceivedAuthHeader = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedHostHeader = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedBody = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedMethod = new AtomicReference<>();

    private final PlaygroundExecutionService service = new PlaygroundExecutionService(
            new TargetUrlPolicy(true, host -> {
                if ("127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host)) {
                    return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
                }
                return new InetAddress[]{InetAddress.getByName("93.184.216.34")};
            }));

    @BeforeAll
    static void startServer() throws IOException {
        testServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverPort = testServer.getAddress().getPort();

        testServer.createContext("/scim/v2/ServiceProviderConfig", exchange -> {
            lastReceivedMethod.set(exchange.getRequestMethod());
            lastReceivedAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            lastReceivedHostHeader.set(exchange.getRequestHeaders().getFirst("Host"));
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
            } else if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
                exchange.sendResponseHeaders(200, -1);
                exchange.close();
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

        testServer.createContext("/scim/v2/huge-chunked", exchange -> {
            byte[] chunk = new byte[64 * 1024];
            java.util.Arrays.fill(chunk, (byte) 'y');
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream os = exchange.getResponseBody()) {
                for (int i = 0; i < 40; i++) {
                    os.write(chunk);
                }
            } catch (IOException ignored) {
                // Client aborts stream once MAX_RESPONSE_BYTES is exceeded
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

    @Test
    void execute_productionPolicy_blocksLocalhostPrivateDnsAndManagementPort() {
        PlaygroundExecutionService strictService = new PlaygroundExecutionService(
                new TargetUrlPolicy(false, host -> new InetAddress[]{InetAddress.getByName("10.0.0.25")}));

        PlaygroundExecuteResponse localRes = strictService.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                "secret-token",
                "GET",
                "/Users",
                null,
                null
        ));
        assertThat(localRes.statusCode()).isEqualTo(0);
        assertThat(localRes.error()).contains("localhost targets are not allowed");

        PlaygroundExecuteResponse rebindRes = strictService.execute(new PlaygroundExecuteRequest(
                "https://rebind.example.com/scim/v2",
                "secret-token",
                "GET",
                "/Users",
                null,
                null
        ));
        assertThat(rebindRes.statusCode()).isEqualTo(0);
        assertThat(rebindRes.error()).contains("private RFC 1918 target addresses are not allowed");

        PlaygroundExecuteResponse mgmtPortRes = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:9090/actuator",
                null,
                "GET",
                "/prometheus",
                null,
                null
        ));
        assertThat(mgmtPortRes.statusCode()).isEqualTo(0);
        assertThat(mgmtPortRes.error()).contains("9090");
    }

    @Test
    void execute_crossOriginEndpointOverride_isRejectedBeforeSendingBearerToken() {
        for (String crossOriginEndpoint : java.util.List.of(
                "https://evil.example.org/exfil",
                "   HTTPS://evil.example.org/exfil   ",
                "   HTTP://127.0.0.1:9999/exfil   ")) {
            PlaygroundExecuteResponse res = service.execute(new PlaygroundExecuteRequest(
                    "http://127.0.0.1:" + serverPort + "/scim/v2",
                    "secret-token-xyz",
                    "GET",
                    crossOriginEndpoint,
                    null,
                    null
            ));

            assertThat(res.statusCode()).isEqualTo(0);
            assertThat(res.error()).contains("configured target origin");
        }

        // Blank endpoint and relative endpoint without leading slash are normalized cleanly
        PlaygroundExecuteResponse blankEndpointRes = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2/ServiceProviderConfig/",
                null,
                "GET",
                "   ",
                null,
                null
        ));
        assertThat(blankEndpointRes.statusCode()).isEqualTo(200);

        PlaygroundExecuteResponse relativeNoSlashRes = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "ServiceProviderConfig",
                null,
                null
        ));
        assertThat(relativeNoSlashRes.statusCode()).isEqualTo(200);
    }

    @Test
    void defaultConstructorUsesStrictProductionPolicy() {
        PlaygroundExecutionService defaultService = new PlaygroundExecutionService();
        PlaygroundExecuteResponse res = defaultService.execute(new PlaygroundExecuteRequest(
                "http://localhost:8080/scim/v2",
                null,
                "GET",
                "/Users",
                null,
                null
        ));

        assertThat(res.statusCode()).isEqualTo(0);
        assertThat(res.error()).contains("localhost targets are not allowed");
    }

    @Test
    void execute_putPatchDeleteHeadOptionsAndUnsupportedMethod_coverAllHttpVerbAndHeaderBranches() {
        java.util.Map<String, String> mixedHeaders = new java.util.HashMap<>();
        mixedHeaders.put("Host", "spoofed.example.com");
        mixedHeaders.put("Connection", "close");
        mixedHeaders.put("   ", "blank-name");
        mixedHeaders.put("X-Null-Header", null);
        mixedHeaders.put("X-Allowed-Custom", "ok-value");

        for (String method : java.util.List.of("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) {
            String body = ("PUT".equals(method) || "PATCH".equals(method)) ? "{\"active\":false}" : null;
            PlaygroundExecuteResponse res = service.execute(new PlaygroundExecuteRequest(
                    "http://127.0.0.1:" + serverPort + "/scim/v2",
                    null,
                    method,
                    "/Users",
                    mixedHeaders,
                    body
            ));
            assertThat(res.statusCode()).isEqualTo(200);
            assertThat(res.requestHeaders()).containsEntry("X-Allowed-Custom", "ok-value");
            assertThat(res.requestHeaders()).doesNotContainKey("Host");
            assertThat(res.requestHeaders()).doesNotContainKey("Connection");
        }

        PlaygroundExecuteResponse unsupported = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "TRACE",
                "/Users",
                null,
                null
        ));
        assertThat(unsupported.statusCode()).isEqualTo(0);
        assertThat(unsupported.error()).contains("Unsupported HTTP method: TRACE");
    }

    @Test
    void execute_sameOriginPortAndDefaultSchemePortComparisonsWork() {
        // Explicit port mismatch on same loopback host -> rejected by sameOrigin
        int otherPort = serverPort == 8081 ? 8082 : 8081;
        PlaygroundExecuteResponse portMismatch = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "http://127.0.0.1:" + otherPort + "/scim/v2/Users",
                null,
                null
        ));
        assertThat(portMismatch.statusCode()).isEqualTo(0);
        assertThat(portMismatch.error()).contains("configured target origin");

        // Default https port 443 matches explicit :443 on same host (passes sameOrigin, then fails connect on .invalid)
        PlaygroundExecutionService httpsOriginService = new PlaygroundExecutionService(
                new TargetUrlPolicy(false, host -> new InetAddress[]{InetAddress.getByName("93.184.216.34")}));
        PlaygroundExecuteResponse explicitPortMismatch = httpsOriginService.execute(new PlaygroundExecuteRequest(
                "https://scim.invalid/scim/v2",
                null,
                "GET",
                "https://scim.invalid:8443/scim/v2/Users",
                null,
                null
        ));
        assertThat(explicitPortMismatch.statusCode()).isEqualTo(0);
        assertThat(explicitPortMismatch.error()).contains("configured target origin");
    }

    @Test
    void execute_dnsRebindingProtection_resolvesOnceAndConnectsStrictlyToPinnedAddress() throws Exception {
        // 1. Stateful HostAddressResolver: returns 127.0.0.1 on lookup #1, and would return 169.254.169.254 on lookup #2
        java.util.concurrent.atomic.AtomicInteger lookupCount = new java.util.concurrent.atomic.AtomicInteger();
        TargetUrlPolicy singleLookupPolicy = new TargetUrlPolicy(true, host -> {
            int call = lookupCount.incrementAndGet();
            if (call == 1) {
                return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
            }
            return new InetAddress[]{InetAddress.getByName("169.254.169.254")};
        });
        PlaygroundExecutionService rebindProtectedService = new PlaygroundExecutionService(singleLookupPolicy);

        PlaygroundExecuteResponse res = rebindProtectedService.execute(new PlaygroundExecuteRequest(
                "http://localhost:" + serverPort + "/scim/v2",
                "secret-token-123",
                "GET",
                "/ServiceProviderConfig",
                null,
                null
        ));
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(lookupCount.get()).isEqualTo(1);

        // 2. Unresolvable hostname in system DNS ("rebind.example.test") succeeds ONLY because HttpClient uses PinnedDnsResolver
        TargetUrlPolicy pinnedCustomHostPolicy = new TargetUrlPolicy(false) {
            @Override
            public ResolvedTarget resolve(String url) {
                try {
                    return new ResolvedTarget(
                            java.net.URI.create(url),
                            "rebind.example.test",
                            java.util.List.of(InetAddress.getByName("127.0.0.1")));
                } catch (java.net.UnknownHostException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        PlaygroundExecutionService pinnedCustomHostService = new PlaygroundExecutionService(pinnedCustomHostPolicy);

        PlaygroundExecuteResponse pinnedRes = pinnedCustomHostService.execute(new PlaygroundExecuteRequest(
                "http://rebind.example.test:" + serverPort + "/scim/v2",
                "secret-token-123",
                "GET",
                "/ServiceProviderConfig",
                null,
                null
        ));
        assertThat(pinnedRes.statusCode()).isEqualTo(200);
        assertThat(lastReceivedHostHeader.get()).isEqualTo("rebind.example.test:" + serverPort);
    }

    @Test
    void execute_chunkedOversizedResponseAndInvalidHeaderCharacters_areRejectedCleanly() {
        PlaygroundExecuteResponse chunkedHuge = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/huge-chunked",
                null,
                null
        ));
        assertThat(chunkedHuge.statusCode()).isEqualTo(0);
        assertThat(chunkedHuge.error()).contains("exceeded maximum allowed size");

        PlaygroundExecuteResponse invalidHeaderName = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/ServiceProviderConfig",
                Map.of("Bad Header Name", "val"),
                null
        ));
        assertThat(invalidHeaderName.statusCode()).isEqualTo(0);
        assertThat(invalidHeaderName.error()).contains("Invalid header name");

        PlaygroundExecuteResponse crlfHeaderValue = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/ServiceProviderConfig",
                Map.of("X-Test", "line1\r\nInjected: true"),
                null
        ));
        assertThat(crlfHeaderValue.statusCode()).isEqualTo(0);
        assertThat(crlfHeaderValue.error()).contains("Invalid header 'X-Test': ***");

        // GET with non-blank body + valid RFC 9110 token punctuation & horizontal tab in header value
        PlaygroundExecuteResponse getWithBodyAndTabHeader = service.execute(new PlaygroundExecuteRequest(
                "http://127.0.0.1:" + serverPort + "/scim/v2",
                null,
                "GET",
                "/ServiceProviderConfig",
                Map.of("X-Token!#$%&'*+.^_`|~9", "tab\tallowed"),
                "{\"ignoredOnGet\":true}"
        ));
        assertThat(getWithBodyAndTabHeader.statusCode()).isEqualTo(200);

        org.apache.http.client.methods.HttpGet dummyGet = new org.apache.http.client.methods.HttpGet("http://127.0.0.1/");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> PlaygroundExecutionService.addValidatedHeader(dummyGet, "", "v"))
                .isInstanceOf(IllegalArgumentException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> PlaygroundExecutionService.addValidatedHeader(dummyGet, "X-Test", null))
                .isInstanceOf(IllegalArgumentException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> PlaygroundExecutionService.addValidatedHeader(dummyGet, "X-Test", "bad\u0007ctl"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
