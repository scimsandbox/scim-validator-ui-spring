package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
    static final int CONNECT_TIMEOUT_MS = 10_000;
    static final int SOCKET_TIMEOUT_MS = 30_000;
    /** Well above any realistic SCIM response; keeps a hostile or huge target from exhausting the heap. */
    static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
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

    private final ObjectMapper objectMapper;
    private final TargetUrlPolicy targetUrlPolicy;

    public PlaygroundExecutionService() {
        this(TargetUrlPolicy.DEFAULT_STRICT);
    }

    @Autowired
    public PlaygroundExecutionService(TargetUrlPolicy targetUrlPolicy) {
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        this.targetUrlPolicy = Objects.requireNonNullElse(targetUrlPolicy, TargetUrlPolicy.DEFAULT_STRICT);
    }

    public PlaygroundExecuteResponse execute(PlaygroundExecuteRequest request) {
        long startTime = System.currentTimeMillis();
        String fullUrl = buildUrl(request.baseUrl(), request.endpoint());
        String method = request.method() != null ? request.method().trim().toUpperCase(Locale.ROOT) : "GET";

        Map<String, String> requestHeadersMap = new LinkedHashMap<>();

        try {
            TargetUrlPolicy.ResolvedTarget baseTarget = targetUrlPolicy.resolve(request.baseUrl());
            URI targetUri = targetUrlPolicy.validateSameOriginUri(baseTarget, fullUrl);

            boolean hasBody = request.body() != null && !request.body().isBlank();
            HttpRequestBase httpRequest = createHttpRequest(method, targetUri, request.body(), hasBody);
            httpRequest.setProtocolVersion(HttpVersion.HTTP_1_1);

            // Add standard or provided Accept header
            String acceptHeader = findHeaderValue(request.headers(), "Accept");
            if (acceptHeader == null) {
                acceptHeader = "application/scim+json, application/json";
            }
            addValidatedHeader(httpRequest, "Accept", acceptHeader);
            requestHeadersMap.put("Accept", acceptHeader);

            // Add Authorization header if token provided
            String authHeader = findHeaderValue(request.headers(), "Authorization");
            if (authHeader == null && request.authToken() != null && !request.authToken().isBlank()) {
                authHeader = "Bearer " + request.authToken().trim();
            }
            if (authHeader != null && !authHeader.isBlank()) {
                addValidatedHeader(httpRequest, "Authorization", authHeader);
                requestHeadersMap.put("Authorization", maskToken(authHeader));
            }

            // Add Content-Type header if body present or explicitly provided
            String contentType = findHeaderValue(request.headers(), "Content-Type");
            if (contentType == null && hasBody) {
                contentType = "application/scim+json; charset=utf-8";
            }
            if (contentType != null) {
                addValidatedHeader(httpRequest, "Content-Type", contentType);
                requestHeadersMap.put("Content-Type", contentType);
            }

            // Add any additional custom headers
            addCustomHeaders(request.headers(), httpRequest, requestHeadersMap);

            try (CloseableHttpClient httpClient = PinnedTargetHttpSupport.createPinnedHttpClient(
                    baseTarget, CONNECT_TIMEOUT_MS, SOCKET_TIMEOUT_MS);
                 CloseableHttpResponse httpResponse = httpClient.execute(httpRequest)) {

                long duration = System.currentTimeMillis() - startTime;
                int statusCode = httpResponse.getStatusLine().getStatusCode();
                String statusText = resolveStatusText(statusCode);

                Map<String, String> responseHeadersMap = extractResponseHeaders(httpResponse);
                String responseBody = readBoundedResponseBody(httpRequest, httpResponse.getEntity());
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
            }
        } catch (IllegalArgumentException ex) {
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.warn("Invalid playground request arguments: {}", detail);
            return PlaygroundExecuteResponse.error("Invalid URL or arguments: " + detail, method, fullUrl, duration);
        } catch (InterruptedIOException ex) {
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
            }
            long duration = System.currentTimeMillis() - startTime;
            String detail = safeMessage(ex, request);
            log.warn("Playground request timed out or interrupted: {}", detail);
            return PlaygroundExecuteResponse.error("Connection failed: " + detail, method, fullUrl, duration);
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
            HttpRequestBase httpRequest,
            Map<String, String> requestHeadersMap) {
        if (headers == null) {
            return;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String val = entry.getValue();
            if (name != null && val != null && !name.isBlank()) {
                String trimmedName = name.trim();
                if (!RESTRICTED_CUSTOM_HEADERS.contains(trimmedName.toLowerCase(Locale.ROOT))) {
                    addValidatedHeader(httpRequest, trimmedName, val);
                    requestHeadersMap.put(trimmedName, val);
                }
            }
        }
    }

    static void addValidatedHeader(HttpRequestBase httpRequest, String name, String value) {
        validateHeaderName(name);
        validateHeaderValue(name, value);
        httpRequest.addHeader(name, value);
    }

    private static void validateHeaderName(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Invalid header name");
        }
        for (int i = 0; i < name.length(); i++) {
            if (!isTokenChar(name.charAt(i))) {
                throw new IllegalArgumentException("Invalid header name");
            }
        }
    }

    private static void validateHeaderValue(String name, String value) {
        if (value == null) {
            throw new IllegalArgumentException("Invalid header '" + name + "': ***");
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '\r' || ch == '\n' || (ch < 0x20 && ch != '\t') || ch >= 0x7F) {
                throw new IllegalArgumentException("Invalid header '" + name + "': ***");
            }
        }
    }

    private static boolean isTokenChar(char ch) {
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            return true;
        }
        return switch (ch) {
            case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' -> true;
            default -> false;
        };
    }

    private static HttpRequestBase createHttpRequest(
            String method,
            URI targetUri,
            String body,
            boolean hasBody) {
        HttpRequestBase request = switch (method) {
            case "GET" -> new HttpGet(targetUri);
            case "POST" -> new HttpPost(targetUri);
            case "PUT" -> new HttpPut(targetUri);
            case "PATCH" -> new HttpPatch(targetUri);
            case "DELETE" -> new HttpDelete(targetUri);
            case "HEAD" -> new HttpHead(targetUri);
            case "OPTIONS" -> new HttpOptions(targetUri);
            default -> throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        };
        if (hasBody && request instanceof HttpEntityEnclosingRequest entityRequest) {
            entityRequest.setEntity(new ByteArrayEntity(body.getBytes(StandardCharsets.UTF_8)));
        }
        return request;
    }

    private static Map<String, String> extractResponseHeaders(CloseableHttpResponse httpResponse) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (Header header : httpResponse.getAllHeaders()) {
            grouped.computeIfAbsent(header.getName(), k -> new ArrayList<>())
                    .add(header.getValue() != null ? header.getValue() : "");
        }
        Map<String, String> responseHeadersMap = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
            responseHeadersMap.put(entry.getKey(), String.join(", ", entry.getValue()));
        }
        return responseHeadersMap;
    }

    private static String readBoundedResponseBody(HttpRequestBase httpRequest, HttpEntity entity) throws IOException {
        if (entity == null) {
            return "";
        }
        if (entity.getContentLength() > MAX_RESPONSE_BYTES) {
            httpRequest.abort();
            throw new IOException("Response body exceeded maximum allowed size of " + MAX_RESPONSE_BYTES + " bytes");
        }
        InputStream in = entity.getContent();
        if (in == null) {
            return "";
        }
        try (InputStream stream = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = stream.read(buffer)) != -1) {
                total += read;
                if (total > MAX_RESPONSE_BYTES) {
                    httpRequest.abort();
                    throw new IOException(
                            "Response body exceeded maximum allowed size of " + MAX_RESPONSE_BYTES + " bytes");
                }
                out.write(buffer, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /**
     * Never log or return a raw exception message without scrubbing caller credentials out of it first.
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
        String path = endpoint != null ? endpoint.trim() : "";
        if (path.regionMatches(true, 0, "http://", 0, 7)
                || path.regionMatches(true, 0, "https://", 0, 8)) {
            return path;
        }

        String base = baseUrl != null ? baseUrl.trim() : "";
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (path.isEmpty()) {
            return base;
        }

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
