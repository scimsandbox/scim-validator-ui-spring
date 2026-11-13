package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class PlaygroundExecutionService {

    private static final Logger log = LoggerFactory.getLogger(PlaygroundExecutionService.class);
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    /** Well above any realistic SCIM response; keeps a hostile or huge target from exhausting the heap. */
    private static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
    /** Pretty-printing parses and re-serialises, so it costs several extra copies of the body. */
    private static final int MAX_PRETTY_PRINT_BYTES = 256 * 1024;
    private static final Set<String> RESTRICTED_CUSTOM_HEADERS = Set.of(
            "accept",
            "authorization",
            "content-type",
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "upgrade"
    );

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final TargetUrlPolicy targetUrlPolicy;

    public PlaygroundExecutionService() {
        this(new TargetUrlPolicy(false));
    }

    @Autowired
    public PlaygroundExecutionService(TargetUrlPolicy targetUrlPolicy) {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        this.targetUrlPolicy = Objects.requireNonNull(targetUrlPolicy, "TargetUrlPolicy must not be null");
    }

    public PlaygroundExecuteResponse execute(PlaygroundExecuteRequest request) {
        long startTime = System.currentTimeMillis();
        String fullUrl = buildUrl(request.baseUrl(), request.endpoint());
        String method = request.method() != null ? request.method().trim().toUpperCase(Locale.ROOT) : "GET";

        Map<String, String> requestHeadersMap = new LinkedHashMap<>();

        try {
            URI baseUri = targetUrlPolicy.validateUri(request.baseUrl());
            URI targetUri = targetUrlPolicy.validateUri(fullUrl);
            if (!sameOrigin(baseUri, targetUri)) {
                throw new IllegalArgumentException("Invalid URL: endpoint must remain on the configured target origin");
            }

            HttpRequest.Builder httpRequestBuilder = HttpRequest.newBuilder()
                    .uri(targetUri)
                    .timeout(REQUEST_TIMEOUT);

            // Add standard or provided Accept header
            String acceptHeader = findHeaderValue(request.headers(), "Accept");
            if (acceptHeader == null) {
                acceptHeader = "application/scim+json, application/json";
            }
            httpRequestBuilder.header("Accept", acceptHeader);
            requestHeadersMap.put("Accept", acceptHeader);

            // Add Authorization header if token provided
            String authHeader = findHeaderValue(request.headers(), "Authorization");
            if (authHeader == null && request.authToken() != null && !request.authToken().isBlank()) {
                authHeader = "Bearer " + request.authToken().trim();
            }
            if (authHeader != null && !authHeader.isBlank()) {
                httpRequestBuilder.header("Authorization", authHeader);
                requestHeadersMap.put("Authorization", maskToken(authHeader));
            }

            // Add Content-Type header if body present or POST/PUT/PATCH
            boolean hasBody = request.body() != null && !request.body().isBlank();
            String contentType = findHeaderValue(request.headers(), "Content-Type");
            if (contentType == null && hasBody) {
                contentType = "application/scim+json; charset=utf-8";
            }
            if (contentType != null) {
                httpRequestBuilder.header("Content-Type", contentType);
                requestHeadersMap.put("Content-Type", contentType);
            }

            // Add any additional custom headers
            addCustomHeaders(request.headers(), httpRequestBuilder, requestHeadersMap);

            // Configure HTTP Method and Body
            configureRequestMethod(httpRequestBuilder, method, request.body(), hasBody);

            HttpRequest httpRequest = httpRequestBuilder.build();
            HttpResponse<String> httpResponse = httpClient.send(httpRequest, responseInfo ->
                    HttpResponse.BodySubscribers.mapping(
                            HttpResponse.BodySubscribers.limiting(
                                    HttpResponse.BodySubscribers.ofByteArray(), MAX_RESPONSE_BYTES),
                            bytes -> new String(bytes, StandardCharsets.UTF_8)));

            long duration = System.currentTimeMillis() - startTime;
            int statusCode = httpResponse.statusCode();
            String statusText = resolveStatusText(statusCode);

            Map<String, String> responseHeadersMap = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> header : httpResponse.headers().map().entrySet()) {
                responseHeadersMap.put(header.getKey(), String.join(", ", header.getValue()));
            }

            String responseBody = httpResponse.body();
            String formattedResponseBody = tryPrettyPrintJson(responseBody);

            return new PlaygroundExecuteResponse(
                    statusCode,
                    statusText,
                    duration,
                    method,
                    fullUrl,
                    requestHeadersMap,
                    request.body(),
                    responseHeadersMap,
                    formattedResponseBody,
                    null
            );

        } catch (IllegalArgumentException ex) {
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.warn("Invalid playground request arguments: {}", detail);
            return PlaygroundExecuteResponse.error("Invalid URL or arguments: " + detail, method, fullUrl, duration);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.warn("Playground request interrupted: {}", detail);
            return PlaygroundExecuteResponse.error("Request interrupted: " + detail, method, fullUrl, duration);
        } catch (IOException ex) {
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.warn("Playground request I/O error: {}", detail);
            return PlaygroundExecuteResponse.error("Connection failed: " + detail, method, fullUrl, duration);
        } catch (Exception ex) {
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.error("Unexpected error executing playground request: {}", detail);
            return PlaygroundExecuteResponse.error("Execution error: " + detail, method, fullUrl, duration);
        }
    }

    private static void addCustomHeaders(
            Map<String, String> headers,
            HttpRequest.Builder httpRequestBuilder,
            Map<String, String> requestHeadersMap) {
        if (headers == null) {
            return;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue();
            if (name != null && val != null && !name.isBlank()
                    && !RESTRICTED_CUSTOM_HEADERS.contains(name.trim().toLowerCase(Locale.ROOT))) {
                httpRequestBuilder.header(name, val);
                requestHeadersMap.put(name, val);
            }
        }
    }

    private static void configureRequestMethod(
            HttpRequest.Builder httpRequestBuilder,
            String method,
            String body,
            boolean hasBody) {
        HttpRequest.BodyPublisher bodyPublisher = hasBody
                ? HttpRequest.BodyPublishers.ofString(body)
                : HttpRequest.BodyPublishers.noBody();

        switch (method) {
            case "GET" -> httpRequestBuilder.GET();
            case "POST" -> httpRequestBuilder.POST(bodyPublisher);
            case "PUT" -> httpRequestBuilder.PUT(bodyPublisher);
            case "PATCH" -> httpRequestBuilder.method("PATCH", bodyPublisher);
            case "DELETE" -> httpRequestBuilder.DELETE();
            case "HEAD" -> httpRequestBuilder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            case "OPTIONS" -> httpRequestBuilder.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
            default -> throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        }
    }

    private static boolean sameOrigin(URI left, URI right) {
        String leftScheme = left.getScheme() != null ? left.getScheme().toLowerCase(Locale.ROOT) : "";
        String rightScheme = right.getScheme() != null ? right.getScheme().toLowerCase(Locale.ROOT) : "";
        String leftHost = left.getHost() != null ? left.getHost().toLowerCase(Locale.ROOT) : "";
        String rightHost = right.getHost() != null ? right.getHost().toLowerCase(Locale.ROOT) : "";
        return leftScheme.equals(rightScheme)
                && leftHost.equals(rightHost)
                && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    /**
     * The JDK embeds the offending header value in its {@code IllegalArgumentException} message,
     * so an exception can carry the caller's bearer token verbatim. Never log or return a raw
     * exception message without scrubbing the token out of it first.
     */
    private String safeMessage(Exception ex, PlaygroundExecuteRequest request) {
        String message = ex.getMessage();
        if (message == null || message.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        for (String secret : secretsOf(request)) {
            message = message.replace(secret, "***");
        }
        return message;
    }

    /**
     * Every string that must never reach a log or the browser: the token field, and an Authorization
     * header supplied directly through the headers map, both whole and without its scheme prefix.
     * Longest first, so replacing a substring cannot mask a longer secret from being matched.
     */
    private List<String> secretsOf(PlaygroundExecuteRequest request) {
        List<String> secrets = new ArrayList<>();
        String token = request.authToken();
        if (token != null && !token.isBlank()) {
            secrets.add(token.trim());
        }
        String headerAuth = findHeaderValue(request.headers(), "Authorization");
        if (headerAuth != null && !headerAuth.isBlank()) {
            String trimmed = headerAuth.trim();
            secrets.add(trimmed);
            int space = trimmed.indexOf(' ');
            if (space > 0 && space + 1 < trimmed.length()) {
                secrets.add(trimmed.substring(space + 1));
            }
        }
        secrets.sort(Comparator.comparingInt(String::length).reversed());
        return secrets;
    }

    private String buildUrl(String baseUrl, String endpoint) {
        if (endpoint != null && (endpoint.startsWith("http://") || endpoint.startsWith("https://"))) {
            return endpoint.trim();
        }

        String base = baseUrl != null ? baseUrl.trim() : "";
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }

        String path = endpoint != null ? endpoint.trim() : "";
        if (!path.startsWith("/") && !path.startsWith("?")) {
            path = "/" + path;
        }

        return base + path;
    }

    private String findHeaderValue(Map<String, String> headers, String headerName) {
        if (headers == null || headerName == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (headerName.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Masks any auth scheme, not just Bearer. Credentials too short to partially reveal are
     * replaced outright rather than echoed back verbatim.
     */
    private String maskToken(String authHeader) {
        if (authHeader == null || authHeader.isBlank()) {
            return authHeader;
        }
        String trimmed = authHeader.trim();
        int space = trimmed.indexOf(' ');
        String scheme = space > 0 ? trimmed.substring(0, space) : "";
        String credential = space > 0 ? trimmed.substring(space + 1) : trimmed;
        String masked = credential.length() > 8
                ? credential.substring(0, 4) + "..." + credential.substring(credential.length() - 4)
                : "***";
        return scheme.isEmpty() ? masked : scheme + " " + masked;
    }

    private String resolveStatusText(int code) {
        try {
            HttpStatus status = HttpStatus.valueOf(code);
            return status.getReasonPhrase();
        } catch (IllegalArgumentException ignored) {
            return "HTTP " + code;
        }
    }

    private String tryPrettyPrintJson(String body) {
        if (body == null || body.isBlank() || body.length() > MAX_PRETTY_PRINT_BYTES) {
            return body;
        }
        try {
            Object json = objectMapper.readValue(body, Object.class);
            return objectMapper.writeValueAsString(json);
        } catch (Exception ignored) {
            return body;
        }
    }
}
