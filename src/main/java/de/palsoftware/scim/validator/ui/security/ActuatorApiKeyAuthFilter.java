package de.palsoftware.scim.validator.ui.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;

/**
 * Protects {@code /actuator/**} endpoints across local and Kubernetes deployments:
 * <ul>
 *     <li>{@code /actuator/health} and {@code /actuator/health/**} are always reachable; if a valid
 *         API key is supplied when configured (or the request arrives on the dedicated management
 *         port {@code managementPort != serverPort} when no key is configured), {@code ROLE_ACTUATOR}
 *         is populated so authorized health components can be inspected when
 *         {@code show-components: when_authorized} is active.</li>
 *     <li>For all other {@code /actuator/**} endpoints (such as {@code /actuator/prometheus}):
 *         <ul>
 *             <li>When {@code app.security.actuator.api-key} is non-blank, a constant-time SHA-256
 *                 comparison of {@code X-Actuator-Api-Key}, {@code X-API-Key}, or
 *                 {@code Authorization: Bearer <key>} is required (HTTP 401 otherwise).</li>
 *             <li>When {@code app.security.actuator.api-key} is blank, access is permitted ONLY on
 *                 the dedicated internal management port ({@code managementPort > 0},
 *                 {@code managementPort != serverPort}, and {@code request.getLocalPort() == managementPort})
 *                 and denied on the public application port.</li>
 *         </ul>
 *     </li>
 * </ul>
 */
public class ActuatorApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER_ACTUATOR_API_KEY = "X-Actuator-Api-Key";
    public static final String HEADER_API_KEY = "X-API-Key";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "bearer ";
    private static final byte[] DUMMY_DIGEST = sha256(new byte[0]);

    private final byte[] expectedKeyDigest;
    private final int managementPort;
    private final int serverPort;

    public ActuatorApiKeyAuthFilter(String configuredApiKey, int managementPort) {
        this(configuredApiKey, managementPort, -1);
    }

    public ActuatorApiKeyAuthFilter(String configuredApiKey, int managementPort, int serverPort) {
        String trimmed = configuredApiKey != null ? configuredApiKey.trim() : "";
        this.expectedKeyDigest = trimmed.isEmpty()
                ? null
                : sha256(trimmed.getBytes(StandardCharsets.UTF_8));
        this.managementPort = managementPort;
        this.serverPort = serverPort;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String rawPath = extractApplicationPath(request);
        if (containsTraversalSegment(rawPath)) {
            if (rawPath.toLowerCase(Locale.ROOT).contains("/actuator")) {
                writeJsonError(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid actuator request path");
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        String normalizedPath = normalizePath(rawPath);
        if (!isActuatorPath(normalizedPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (isHealthPath(normalizedPath)) {
            if (expectedKeyDigest != null) {
                if (hasValidApiKey(request)) {
                    authenticateActuatorCaller();
                }
            } else if (isDedicatedManagementPortRequest(request)) {
                authenticateActuatorCaller();
            }
            filterChain.doFilter(request, response);
            return;
        }

        if (expectedKeyDigest != null) {
            if (!hasValidApiKey(request)) {
                response.setHeader("WWW-Authenticate", "Bearer realm=\"actuator\"");
                writeJsonError(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return;
            }
            authenticateActuatorCaller();
            filterChain.doFilter(request, response);
            return;
        }

        if (isDedicatedManagementPortRequest(request)) {
            authenticateActuatorCaller();
            filterChain.doFilter(request, response);
            return;
        }

        writeJsonError(response, HttpServletResponse.SC_FORBIDDEN, "Actuator endpoint is restricted to the management port");
    }

    private boolean isDedicatedManagementPortRequest(HttpServletRequest request) {
        return managementPort > 0
                && managementPort != serverPort
                && request.getLocalPort() == managementPort;
    }

    private boolean hasValidApiKey(HttpServletRequest request) {
        String candidate = extractCandidateKey(request);
        if (candidate == null || candidate.isEmpty()) {
            MessageDigest.isEqual(expectedKeyDigest, DUMMY_DIGEST);
            return false;
        }
        byte[] providedDigest = sha256(candidate.getBytes(StandardCharsets.UTF_8));
        return MessageDigest.isEqual(expectedKeyDigest, providedDigest);
    }

    private static String extractCandidateKey(HttpServletRequest request) {
        String actuatorKeyHeader = request.getHeader(HEADER_ACTUATOR_API_KEY);
        if (actuatorKeyHeader != null && !actuatorKeyHeader.isBlank()) {
            return actuatorKeyHeader.trim();
        }
        String apiKeyHeader = request.getHeader(HEADER_API_KEY);
        if (apiKeyHeader != null && !apiKeyHeader.isBlank()) {
            return apiKeyHeader.trim();
        }
        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.length() > BEARER_PREFIX.length()
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = authHeader.substring(BEARER_PREFIX.length()).trim();
            if (!token.isEmpty()) {
                return token;
            }
        }
        return null;
    }

    private static void authenticateActuatorCaller() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "actuator-client",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ACTUATOR"))));
        SecurityContextHolder.setContext(context);
    }

    private static String extractApplicationPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null || uri.isEmpty()) {
            String servletPath = request.getServletPath();
            return servletPath != null ? servletPath : "";
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    private static boolean containsTraversalSegment(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.contains("%2e") || lower.contains("%2f") || lower.contains("\\")) {
            return true;
        }
        String[] segments = path.split("/");
        for (String segment : segments) {
            int semicolon = segment.indexOf(';');
            String clean = semicolon >= 0 ? segment.substring(0, semicolon) : segment;
            if ("..".equals(clean) || ".".equals(clean)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizePath(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return "/";
        }
        StringBuilder sb = new StringBuilder(rawPath.length());
        String[] segments = rawPath.split("/");
        for (String segment : segments) {
            int semicolon = segment.indexOf(';');
            String clean = semicolon >= 0 ? segment.substring(0, semicolon) : segment;
            if (!clean.isEmpty()) {
                sb.append('/').append(clean);
            }
        }
        return sb.isEmpty() ? "/" : sb.toString();
    }

    private static boolean isActuatorPath(String normalizedPath) {
        return "/actuator".equals(normalizedPath) || normalizedPath.startsWith("/actuator/");
    }

    private static boolean isHealthPath(String normalizedPath) {
        return "/actuator/health".equals(normalizedPath) || normalizedPath.startsWith("/actuator/health/");
    }

    private static void writeJsonError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 MessageDigest algorithm unavailable", ex);
        }
    }
}
