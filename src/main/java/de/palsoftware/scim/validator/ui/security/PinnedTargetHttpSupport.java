package de.palsoftware.scim.validator.ui.security;

import io.restassured.RestAssured;
import io.restassured.authentication.CertAuthScheme;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.filter.OrderedFilter;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.HttpInetSocketAddress;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.opentest4j.TestAbortedException;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolver.LookupPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/**
 * Pins outbound HTTP client connections (Apache HttpClient 4.5, RestAssured legacy HttpClient via
 * public {@link SchemeRegistry} socket factories, and JDK {@link java.net.http.HttpClient} via
 * {@link PinnedInetAddressResolverProvider}) to the exact {@link InetAddress} list validated by
 * {@link TargetUrlPolicy#resolve(String)}, preventing DNS-rebinding (TOCTOU) attacks while
 * preserving the original hostname for the HTTP {@code Host} header, TLS SNI, and RFC 6125 X.509
 * certificate hostname verification.
 */
public final class PinnedTargetHttpSupport {

    static final int DEFAULT_REST_ASSURED_CONNECT_TIMEOUT_MS = 10_000;
    static final int DEFAULT_REST_ASSURED_SOCKET_TIMEOUT_MS = 60_000;
    static final long DEFAULT_REST_ASSURED_CONN_MANAGER_TIMEOUT_MS = 10_000L;

    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_HTTPS = "https";
    private static final String MSG_TARGET_REQUIRED = "ResolvedTarget must not be null";
    private static final String MSG_PINNED_RESOLVER_REQUIRED = "Pinned DnsResolver must not be null";
    private static final String MSG_MISSING_HOST = "Invalid URL: target must include a host";

    private static final ConcurrentHashMap<String, CopyOnWriteArrayList<PinRegistration>> ACTIVE_PINS =
            new ConcurrentHashMap<>();
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<PinnedScopeImpl> CURRENT_SCOPE = new ThreadLocal<>();
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<Boolean> BYPASS_PIN = new ThreadLocal<>();
    private static final OrderedFilter REST_ASSURED_FILTER = new PinnedRestAssuredFilter();

    static {
        PinnedInetAddressResolverProvider.RESOLVER_HOOK.set(PinnedTargetHttpSupport::lookupWithActivePins);
        ensureRestAssuredFilterInstalled();
    }

    private PinnedTargetHttpSupport() {
    }

    @FunctionalInterface
    public interface PinnedScope extends AutoCloseable {
        @Override
        void close();
    }

    static final class PinRegistration {
        final List<InetAddress> addresses;

        PinRegistration(List<InetAddress> addresses) {
            this.addresses = addresses;
        }
    }

    static void installBuiltinResolver(InetAddressResolver resolver) {
        PinnedInetAddressResolverProvider.BUILTIN_RESOLVER.set(
                Objects.requireNonNull(resolver, "InetAddressResolver must not be null"));
    }

    static InetAddressResolver currentBuiltinResolver() {
        return PinnedInetAddressResolverProvider.BUILTIN_RESOLVER.get();
    }

    /**
     * Ensures the JVM {@link java.util.ServiceLoader} has initialized {@link PinnedInetAddressResolverProvider}
     * under the current context {@link ClassLoader} (critical for Spring Boot's {@code LaunchedClassLoader}).
     */
    public static void initializeJvmDnsPinning() {
        PinnedInetAddressResolverProvider.RESOLVER_HOOK.set(PinnedTargetHttpSupport::lookupWithActivePins);
        if (PinnedInetAddressResolverProvider.BUILTIN_RESOLVER.get() != null) {
            return;
        }
        Boolean previous = BYPASS_PIN.get();
        BYPASS_PIN.set(Boolean.TRUE);
        try {
            InetAddress.getAllByName("localhost");
        } catch (UnknownHostException ignored) {
            // Resolver bootstrap completed even if "localhost" is unmapped
        } finally {
            restoreBypassFlag(previous);
        }
    }

    /**
     * Resolves {@code host} directly through the platform's built-in {@link InetAddressResolver},
     * bypassing both active pins and {@code InetAddress}'s JVM-wide cache so {@link TargetUrlPolicy}
     * always performs live DNS validation without polluting {@code InetAddress.cache} on rejected hosts.
     */
    public static InetAddress[] resolveUnpinned(String host) throws UnknownHostException {
        initializeJvmDnsPinning();
        InetAddressResolver resolver = PinnedInetAddressResolverProvider.BUILTIN_RESOLVER.get();
        if (resolver != null) {
            InetAddress[] resolved = resolver
                    .lookupByName(host, LookupPolicy.of(LookupPolicy.IPV4 | LookupPolicy.IPV6))
                    .toArray(InetAddress[]::new);
            if (resolved.length == 0) {
                throw new UnknownHostException(host);
            }
            return resolved;
        }
        Boolean previous = BYPASS_PIN.get();
        BYPASS_PIN.set(Boolean.TRUE);
        try {
            return InetAddress.getAllByName(host);
        } finally {
            restoreBypassFlag(previous);
        }
    }

    private static void restoreBypassFlag(Boolean previous) {
        if (Boolean.TRUE.equals(previous)) {
            BYPASS_PIN.set(Boolean.TRUE);
        } else {
            BYPASS_PIN.remove();
        }
    }

    public static DnsResolver dnsResolverFor(TargetUrlPolicy.ResolvedTarget target) {
        Objects.requireNonNull(target, MSG_TARGET_REQUIRED);
        return new PinnedDnsResolver(target);
    }

    public static CloseableHttpClient createPinnedHttpClient(
            TargetUrlPolicy.ResolvedTarget target,
            int connectTimeoutMs,
            int socketTimeoutMs) {
        DnsResolver dnsResolver = dnsResolverFor(target);
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(SCHEME_HTTP, PlainConnectionSocketFactory.getSocketFactory())
                .register(SCHEME_HTTPS, SSLConnectionSocketFactory.getSystemSocketFactory())
                .build();

        BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(
                socketFactoryRegistry,
                null,
                null,
                dnsResolver);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeoutMs)
                .setConnectionRequestTimeout(socketTimeoutMs)
                .setSocketTimeout(socketTimeoutMs)
                .build();

        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .disableCookieManagement()
                .build();
    }

    public static PinnedScope pin(TargetUrlPolicy.ResolvedTarget target) {
        Objects.requireNonNull(target, MSG_TARGET_REQUIRED);
        ensureRestAssuredFilterInstalled();

        String normalizedHost = normalizeDnsHost(target.host());
        PinRegistration registration = new PinRegistration(target.addresses());
        ACTIVE_PINS.compute(normalizedHost, (k, list) -> {
            CopyOnWriteArrayList<PinRegistration> registrations =
                    list != null ? list : new CopyOnWriteArrayList<>();
            registrations.add(registration);
            return registrations;
        });

        PinnedScopeImpl previous = CURRENT_SCOPE.get();
        PinnedScopeImpl scope = new PinnedScopeImpl(target, normalizedHost, registration, previous);
        CURRENT_SCOPE.set(scope);
        return scope;
    }

    public static TargetUrlPolicy.ResolvedTarget currentPinnedTarget() {
        PinnedScopeImpl scope = CURRENT_SCOPE.get();
        return (scope != null && !scope.isClosed()) ? scope.target() : null;
    }

    static PinnedScopeImpl currentScopeForTesting() {
        return CURRENT_SCOPE.get();
    }

    static boolean hasActivePinForHost(String rawHost) {
        CopyOnWriteArrayList<PinRegistration> list = ACTIVE_PINS.get(normalizeDnsHost(rawHost));
        return list != null && !list.isEmpty();
    }

    public static synchronized void ensureRestAssuredFilterInstalled() {
        List<Filter> currentFilters = RestAssured.filters();
        for (Filter filter : currentFilters) {
            if (filter instanceof PinnedRestAssuredFilter) {
                return;
            }
        }
        RestAssured.filters(REST_ASSURED_FILTER);
    }

    /**
     * Validates a RestAssured request URL executed inside a pinned SCIM validator scope, matching
     * {@code scim-validator}'s {@code ScimUrlSecurity} contract:
     * <ul>
     *     <li>Malformed, non-HTTP(S), protocol-relative, credential-bearing, control-character,
     *         loopback management-port, or root-escaping URLs fail immediately with
     *         {@link IllegalArgumentException}.</li>
     *     <li>Exact same-origin URLs and same-host {@code http -> https} upgrades on port {@code 443}
     *         are allowed.</li>
     *     <li>Syntactically valid {@code http}/{@code https} URLs pointing to an untrusted origin or
     *         {@code https -> http} downgrade abort the current test via {@link TestAbortedException}
     *         without forwarding credentials.</li>
     * </ul>
     */
    public static URI validateValidatorRequestUri(TargetUrlPolicy.ResolvedTarget baseTarget, String candidateUrl) {
        Objects.requireNonNull(baseTarget, MSG_TARGET_REQUIRED);
        URI candidateUri = parseAndValidateFollowUpUri(candidateUrl);

        String candidateScheme = Objects.requireNonNull(candidateUri.getScheme()).toLowerCase(Locale.ROOT);
        int candidatePort = TargetUrlPolicy.effectivePort(candidateScheme, candidateUri.getPort());
        String canonicalCandidateHost = normalizeDnsHost(candidateUri.getHost());
        if (canonicalCandidateHost.isEmpty()) {
            throw new IllegalArgumentException(MSG_MISSING_HOST);
        }
        if (baseTarget.isBlockedLoopbackManagementPort(candidatePort)) {
            throw new IllegalArgumentException(
                    "Invalid URL: management port " + baseTarget.managementPort() + " is not allowed");
        }

        if (isAllowedOriginOrHttpsUpgrade(baseTarget, candidateScheme, canonicalCandidateHost, candidatePort)) {
            return candidateUri;
        }

        String baseScheme = Objects.requireNonNull(baseTarget.uri().getScheme()).toLowerCase(Locale.ROOT);
        String canonicalBaseHost = normalizeDnsHost(baseTarget.host());
        int basePort = TargetUrlPolicy.effectivePort(baseScheme, baseTarget.uri().getPort());
        throw new TestAbortedException(
                "Skipped follow-up request to '" + candidateUri
                        + "': target origin does not match configured SCIM origin "
                        + baseScheme + "://" + canonicalBaseHost + ":" + basePort
                        + " (refusing to forward credentials cross-origin or across scheme downgrade)");
    }

    private static URI parseAndValidateFollowUpUri(String candidateUrl) {
        if (candidateUrl == null || candidateUrl.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        if (containsUnsafeUrlCharacters(candidateUrl)) {
            throw new IllegalArgumentException("Invalid URL: control or backslash characters are not allowed");
        }
        String trimmed = candidateUrl.trim();
        if (trimmed.startsWith("//")) {
            throw new IllegalArgumentException("Invalid URL: protocol-relative URLs are not allowed");
        }
        URI candidateUri;
        try {
            candidateUri = new URI(trimmed);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid URL: malformed target URI", ex);
        }
        validateFollowUpHttpComponents(candidateUri);
        return candidateUri;
    }

    private static void validateFollowUpHttpComponents(URI uri) {
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : null;
        if (!SCHEME_HTTP.equals(scheme) && !SCHEME_HTTPS.equals(scheme)) {
            throw new IllegalArgumentException("Invalid URL: only http and https targets are allowed");
        }
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Invalid URL: userinfo credentials in target URL are not allowed");
        }
        String rawHost = uri.getHost();
        if (rawHost == null || rawHost.isBlank()) {
            throw new IllegalArgumentException(MSG_MISSING_HOST);
        }
        if (rawHost.contains("%")) {
            throw new IllegalArgumentException("Invalid URL: IPv6 zone identifiers are not allowed");
        }
        if (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535)) {
            throw new IllegalArgumentException("Invalid URL: port out of valid range");
        }
        if (hasLeadingParentTraversal(uri.normalize().getRawPath())) {
            throw new IllegalArgumentException("Invalid URL: path must not escape root via dot-segments");
        }
    }

    private static boolean isAllowedOriginOrHttpsUpgrade(
            TargetUrlPolicy.ResolvedTarget baseTarget,
            String candidateScheme,
            String canonicalCandidateHost,
            int candidatePort) {
        String canonicalBaseHost = normalizeDnsHost(baseTarget.host());
        if (!canonicalBaseHost.equals(canonicalCandidateHost)) {
            return false;
        }
        String baseScheme = Objects.requireNonNull(baseTarget.uri().getScheme()).toLowerCase(Locale.ROOT);
        int basePort = TargetUrlPolicy.effectivePort(baseScheme, baseTarget.uri().getPort());
        if (baseScheme.equals(candidateScheme) && basePort == candidatePort) {
            return true;
        }
        return SCHEME_HTTP.equals(baseScheme)
                && SCHEME_HTTPS.equals(candidateScheme)
                && candidatePort == 443;
    }

    static boolean containsUnsafeUrlCharacters(String value) {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch <= 0x1F || ch == 0x7F || ch == '\\') {
                return true;
            }
        }
        return false;
    }

    static boolean hasLeadingParentTraversal(String rawPath) {
        return "/..".equals(rawPath) || (rawPath != null && rawPath.startsWith("/../"));
    }

    static URI ensureNonEmptyPath(URI uri) {
        if (uri == null || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())) {
            return uri;
        }
        StringBuilder sb = new StringBuilder()
                .append(uri.getScheme())
                .append("://")
                .append(uri.getRawAuthority())
                .append('/');
        if (uri.getRawQuery() != null) {
            sb.append('?').append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null) {
            sb.append('#').append(uri.getRawFragment());
        }
        return URI.create(sb.toString());
    }

    public static String normalizeDnsHost(String rawHost) {
        if (rawHost == null) {
            return "";
        }
        String trimmed = rawHost.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        String host = stripBracketsOrTrailingDots(trimmed).toLowerCase(Locale.ROOT);
        return tryCanonicalizeIpLiteral(host);
    }

    private static String stripBracketsOrTrailingDots(String trimmed) {
        if (trimmed.startsWith("[") && trimmed.endsWith("]") && trimmed.length() > 2) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        String host = trimmed;
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (containsNonAscii(host)) {
            try {
                return IDN.toASCII(host, IDN.ALLOW_UNASSIGNED);
            } catch (IllegalArgumentException ignored) {
                return host;
            }
        }
        return host;
    }

    private static String tryCanonicalizeIpLiteral(String lowerHost) {
        if (!lowerHost.isEmpty() && !lowerHost.contains("%") && looksLikeIpLiteral(lowerHost)) {
            try {
                return InetAddress.ofLiteral(lowerHost).getHostAddress().toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException ignored) {
                return lowerHost;
            }
        }
        return lowerHost;
    }

    private static boolean containsNonAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) >= 0x80) {
                return true;
            }
        }
        return false;
    }

    private static boolean looksLikeIpLiteral(String host) {
        if (host.indexOf(':') >= 0) {
            return true;
        }
        char first = host.charAt(0);
        if (first < '0' || first > '9') {
            return false;
        }
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            if ((ch < '0' || ch > '9') && ch != '.') {
                return false;
            }
        }
        return true;
    }

    static int resolveConnectTimeoutMs() {
        return resolvePositiveIntConfig(
                System.getProperty("scim.http.connectTimeoutMs"),
                System.getenv("SCIM_HTTP_CONNECT_TIMEOUT_MS"),
                DEFAULT_REST_ASSURED_CONNECT_TIMEOUT_MS);
    }

    static int resolveSocketTimeoutMs() {
        return resolvePositiveIntConfig(
                System.getProperty("scim.http.socketTimeoutMs"),
                System.getenv("SCIM_HTTP_SOCKET_TIMEOUT_MS"),
                DEFAULT_REST_ASSURED_SOCKET_TIMEOUT_MS);
    }

    static long resolveConnectionManagerTimeoutMs() {
        return resolvePositiveLongConfig(
                System.getProperty("scim.http.connectionManagerTimeoutMs"),
                System.getenv("SCIM_HTTP_CONNECTION_MANAGER_TIMEOUT_MS"),
                DEFAULT_REST_ASSURED_CONN_MANAGER_TIMEOUT_MS);
    }

    static int resolvePositiveIntConfig(String sysPropValue, String envValue, int defaultValue) {
        long parsed = resolvePositiveLongConfig(sysPropValue, envValue, defaultValue);
        return parsed > Integer.MAX_VALUE ? defaultValue : (int) parsed;
    }

    static long resolvePositiveLongConfig(String sysPropValue, String envValue, long defaultValue) {
        long fromSysProp = tryParsePositiveLong(sysPropValue);
        if (fromSysProp > 0) {
            return fromSysProp;
        }
        long fromEnv = tryParsePositiveLong(envValue);
        return fromEnv > 0 ? fromEnv : defaultValue;
    }

    private static long tryParsePositiveLong(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return -1L;
        }
        try {
            long parsed = Long.parseLong(rawValue.trim());
            return parsed > 0 ? parsed : -1L;
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    static HttpInetSocketAddress resolvePinnedConnectAddress(
            DnsResolver pinnedDnsResolver,
            InetSocketAddress remoteAddress,
            String defaultScheme) throws UnknownHostException {
        Objects.requireNonNull(remoteAddress, "Remote address must not be null");
        HttpHost httpHost = (remoteAddress instanceof HttpInetSocketAddress httpInet)
                ? httpInet.getHttpHost()
                : new HttpHost(remoteAddress.getHostString(), remoteAddress.getPort(), defaultScheme);
        InetAddress[] allowed = pinnedDnsResolver.resolve(httpHost.getHostName());
        if (allowed == null || allowed.length == 0) {
            throw new UnknownHostException("No pinned addresses available for host: " + httpHost.getHostName());
        }
        InetAddress chosen = choosePinnedAddress(remoteAddress.getAddress(), allowed);
        return new HttpInetSocketAddress(httpHost, chosen, remoteAddress.getPort());
    }

    private static InetAddress choosePinnedAddress(InetAddress candidate, InetAddress[] allowed) {
        if (candidate != null) {
            for (InetAddress addr : allowed) {
                if (addr.equals(candidate)) {
                    return addr;
                }
            }
        }
        return allowed[0];
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class PinnedPlainSocketFactory extends PlainSocketFactory {
        private final DnsResolver pinnedDnsResolver;

        PinnedPlainSocketFactory(DnsResolver pinnedDnsResolver) {
            this.pinnedDnsResolver = Objects.requireNonNull(pinnedDnsResolver, MSG_PINNED_RESOLVER_REQUIRED);
        }

        @Override
        public Socket connectSocket(
                Socket sock,
                InetSocketAddress remoteAddress,
                InetSocketAddress localAddress,
                HttpParams params) throws IOException, ConnectTimeoutException {
            HttpInetSocketAddress pinnedRemote =
                    resolvePinnedConnectAddress(pinnedDnsResolver, remoteAddress, SCHEME_HTTP);
            return super.connectSocket(sock, pinnedRemote, localAddress, params);
        }
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class PinnedStrictHttpsSocketFactory extends SSLSocketFactory {
        private final DnsResolver pinnedDnsResolver;

        PinnedStrictHttpsSocketFactory(DnsResolver pinnedDnsResolver) {
            super(
                    (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault(),
                    SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
            this.pinnedDnsResolver = Objects.requireNonNull(pinnedDnsResolver, MSG_PINNED_RESOLVER_REQUIRED);
        }

        @Override
        protected void prepareSocket(SSLSocket socket) throws IOException {
            SSLParameters sslParams = socket.getSSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(sslParams);
        }

        @Override
        public Socket connectSocket(
                Socket socket,
                InetSocketAddress remoteAddress,
                InetSocketAddress localAddress,
                HttpParams params) throws IOException, UnknownHostException, ConnectTimeoutException {
            HttpInetSocketAddress pinnedRemote =
                    resolvePinnedConnectAddress(pinnedDnsResolver, remoteAddress, SCHEME_HTTPS);
            return super.connectSocket(socket, pinnedRemote, localAddress, params);
        }
    }

    static final class SafePinnedRedirectStrategy extends DefaultRedirectStrategy {
        static final int DEFAULT_MAX_REDIRECTS = 5;
        private static final int HTTP_TEMPORARY_REDIRECT = 307;
        private static final int HTTP_PERMANENT_REDIRECT = 308;
        private static final Set<String> PRESERVED_BODY_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

        private final TargetUrlPolicy.ResolvedTarget baseTarget;
        private final String canonicalBaseHost;

        SafePinnedRedirectStrategy(TargetUrlPolicy.ResolvedTarget baseTarget) {
            this.baseTarget = Objects.requireNonNull(baseTarget, MSG_TARGET_REQUIRED);
            this.canonicalBaseHost = normalizeDnsHost(baseTarget.host());
        }

        @Override
        public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context)
                throws ProtocolException {
            if (!hasValidRequestAndResponse(request, response)) {
                return false;
            }
            Header locationHeader = response.getFirstHeader("location");
            String rawLocation = locationHeader != null ? locationHeader.getValue() : null;
            if (isUnsafeOrBlankRedirectLocation(rawLocation)) {
                return false;
            }
            if (!isSupportedRedirectStatusAndMethod(request, response, context)) {
                return false;
            }
            HttpHost targetHost = extractTargetHost(context);
            return targetHost != null && isAllowedRedirectDestination(request, targetHost, rawLocation.trim());
        }

        private static boolean hasValidRequestAndResponse(HttpRequest request, HttpResponse response) {
            return request != null
                    && request.getRequestLine() != null
                    && response != null
                    && response.getStatusLine() != null;
        }

        private static boolean isUnsafeOrBlankRedirectLocation(String rawLocation) {
            return rawLocation == null
                    || rawLocation.isBlank()
                    || containsUnsafeUrlCharacters(rawLocation)
                    || rawLocation.trim().startsWith("//");
        }

        private boolean isSupportedRedirectStatusAndMethod(
                HttpRequest request,
                HttpResponse response,
                HttpContext context) throws ProtocolException {
            int statusCode = response.getStatusLine().getStatusCode();
            String rawMethod = request.getRequestLine().getMethod();
            String method = rawMethod != null ? rawMethod.toUpperCase(Locale.ROOT) : "";
            boolean methodPreserving = (statusCode == HTTP_TEMPORARY_REDIRECT || statusCode == HTTP_PERMANENT_REDIRECT)
                    && PRESERVED_BODY_METHODS.contains(method);
            return super.isRedirected(request, response, context) || methodPreserving;
        }

        private static HttpHost extractTargetHost(HttpContext context) {
            Object attr = context != null ? context.getAttribute(HttpCoreContext.HTTP_TARGET_HOST) : null;
            if (attr instanceof HttpHost host && host.getSchemeName() != null && host.getHostName() != null) {
                return host;
            }
            return null;
        }

        private boolean isAllowedRedirectDestination(
                HttpRequest request,
                HttpHost targetHost,
                String trimmedLocation) {
            try {
                URI currentOrigin = new URI(
                        targetHost.getSchemeName(),
                        null,
                        targetHost.getHostName(),
                        targetHost.getPort(),
                        "/",
                        null,
                        null);
                URI targetUri = resolveRedirectTargetUri(request, targetHost, trimmedLocation);
                return isPermittedRedirectTransition(currentOrigin, targetUri);
            } catch (URISyntaxException ignored) {
                return false;
            }
        }

        private boolean isPermittedRedirectTransition(URI currentOrigin, URI targetUri) {
            if (!isValidRedirectEndpointUri(currentOrigin) || !isValidRedirectEndpointUri(targetUri)) {
                return false;
            }
            String currentCanonicalHost = normalizeDnsHost(currentOrigin.getHost());
            String targetCanonicalHost = normalizeDnsHost(targetUri.getHost());
            if (!canonicalBaseHost.equals(targetCanonicalHost) || !currentCanonicalHost.equals(targetCanonicalHost)) {
                return false;
            }
            String currentScheme = currentOrigin.getScheme().toLowerCase(Locale.ROOT);
            String targetScheme = targetUri.getScheme().toLowerCase(Locale.ROOT);
            int currentPort = TargetUrlPolicy.effectivePort(currentScheme, currentOrigin.getPort());
            int targetPort = TargetUrlPolicy.effectivePort(targetScheme, targetUri.getPort());
            if (baseTarget.isBlockedLoopbackManagementPort(targetPort)) {
                return false;
            }
            if (currentScheme.equals(targetScheme) && currentPort == targetPort) {
                return true;
            }
            return SCHEME_HTTP.equals(currentScheme)
                    && SCHEME_HTTPS.equals(targetScheme)
                    && targetPort == 443;
        }

        private static boolean isValidRedirectEndpointUri(URI uri) {
            if (uri == null || uri.getScheme() == null || uri.getRawUserInfo() != null) {
                return false;
            }
            String host = uri.getHost();
            if (host == null || host.isBlank() || host.contains("%")) {
                return false;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            if (!SCHEME_HTTP.equals(scheme) && !SCHEME_HTTPS.equals(scheme)) {
                return false;
            }
            if (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535)) {
                return false;
            }
            return !hasLeadingParentTraversal(uri.normalize().getRawPath());
        }

        private static URI resolveRedirectTargetUri(
                HttpRequest request,
                HttpHost targetHost,
                String trimmedLocation) throws URISyntaxException {
            URI candidate = new URI(trimmedLocation);
            if (candidate.isAbsolute()) {
                return candidate.normalize();
            }
            URI requestUri = new URI(request.getRequestLine().getUri());
            URI absoluteRequestUri = requestUri.isAbsolute()
                    ? requestUri
                    : URIUtils.rewriteURI(requestUri, targetHost, URIUtils.DROP_FRAGMENT);
            URI baseForResolve = ensureNonEmptyPath(absoluteRequestUri);
            return baseForResolve.resolve(candidate).normalize();
        }
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class PinnedScopeImpl implements PinnedScope {
        private final TargetUrlPolicy.ResolvedTarget target;
        private final String normalizedHost;
        private final PinRegistration registration;
        private final PinnedScopeImpl previous;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final Set<ClientConnectionManager> trackedConnectionManagers = ConcurrentHashMap.newKeySet();

        PinnedScopeImpl(
                TargetUrlPolicy.ResolvedTarget target,
                String normalizedHost,
                PinRegistration registration,
                PinnedScopeImpl previous) {
            this.target = target;
            this.normalizedHost = normalizedHost;
            this.registration = registration;
            this.previous = previous;
        }

        TargetUrlPolicy.ResolvedTarget target() {
            return target;
        }

        boolean isClosed() {
            return closed.get();
        }

        void trackConnectionManager(ClientConnectionManager connManager) {
            Objects.requireNonNull(connManager, "ClientConnectionManager must not be null");
            synchronized (this) {
                if (closed.get()) {
                    connManager.shutdown();
                    throw new IllegalStateException("Pinned HTTP scope is already closed");
                }
                trackedConnectionManagers.add(connManager);
            }
        }

        int trackedConnectionManagerCount() {
            return trackedConnectionManagers.size();
        }

        @Override
        public void close() {
            List<ClientConnectionManager> managersToShutdown;
            synchronized (this) {
                if (!closed.compareAndSet(false, true)) {
                    return;
                }
                managersToShutdown = List.copyOf(trackedConnectionManagers);
                trackedConnectionManagers.clear();
            }
            restoreThreadLocalScope();
            ACTIVE_PINS.computeIfPresent(normalizedHost, (k, list) -> {
                list.remove(registration);
                return list.isEmpty() ? null : list;
            });
            for (ClientConnectionManager manager : managersToShutdown) {
                manager.shutdown();
            }
        }

        private void restoreThreadLocalScope() {
            if (CURRENT_SCOPE.get() != this) {
                return;
            }
            PinnedScopeImpl ancestor = previous;
            while (ancestor != null && ancestor.isClosed()) {
                ancestor = ancestor.previous;
            }
            if (ancestor == null) {
                CURRENT_SCOPE.remove();
            } else {
                CURRENT_SCOPE.set(ancestor);
            }
        }
    }

    static final class PinnedDnsResolver implements DnsResolver {
        private final String canonicalTargetHost;
        private final List<InetAddress> addresses;

        PinnedDnsResolver(TargetUrlPolicy.ResolvedTarget target) {
            Objects.requireNonNull(target, MSG_TARGET_REQUIRED);
            this.canonicalTargetHost = normalizeDnsHost(target.host());
            this.addresses = target.addresses();
        }

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            String normalized = normalizeDnsHost(host);
            if (normalized.isEmpty() || !normalized.equals(canonicalTargetHost)) {
                throw new UnknownHostException("Blocked outbound connection to unpinned host: " + host);
            }
            return addresses.toArray(InetAddress[]::new);
        }
    }

    static Stream<InetAddress> lookupWithActivePins(
            String host,
            LookupPolicy lookupPolicy,
            InetAddressResolver delegate) throws UnknownHostException {
        if (Boolean.TRUE.equals(BYPASS_PIN.get())) {
            return delegate.lookupByName(host, lookupPolicy);
        }
        String normalized = normalizeDnsHost(host);
        if (!normalized.isEmpty()) {
            CopyOnWriteArrayList<PinRegistration> registrations = ACTIVE_PINS.get(normalized);
            if (registrations != null) {
                PinRegistration[] snapshot = registrations.toArray(PinRegistration[]::new);
                if (snapshot.length > 0) {
                    return PinnedInetAddressResolver.applyLookupPolicy(
                            snapshot[snapshot.length - 1].addresses, lookupPolicy);
                }
            }
        }
        return delegate.lookupByName(host, lookupPolicy);
    }

    static final class PinnedInetAddressResolver implements InetAddressResolver {
        private final InetAddressResolver delegate;

        PinnedInetAddressResolver(InetAddressResolver delegate) {
            this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        }

        @Override
        public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) throws UnknownHostException {
            return lookupWithActivePins(host, lookupPolicy, delegate);
        }

        @Override
        public String lookupByAddress(byte[] addr) throws UnknownHostException {
            return delegate.lookupByAddress(addr);
        }

        static Stream<InetAddress> applyLookupPolicy(List<InetAddress> pinned, LookupPolicy lookupPolicy) {
            if (lookupPolicy == null) {
                return pinned.stream();
            }
            int characteristics = lookupPolicy.characteristics();
            boolean wantIpv4 = (characteristics & LookupPolicy.IPV4) != 0;
            boolean wantIpv6 = (characteristics & LookupPolicy.IPV6) != 0;

            if (wantIpv4 != wantIpv6) {
                List<InetAddress> filtered = pinned.stream()
                        .filter(addr -> wantIpv4 ? addr instanceof Inet4Address : addr instanceof Inet6Address)
                        .toList();
                return filtered.isEmpty() ? pinned.stream() : filtered.stream();
            }

            if ((characteristics & LookupPolicy.IPV4_FIRST) != 0
                    || (characteristics & LookupPolicy.IPV6_FIRST) != 0) {
                return reorderByAddressFamily(pinned, (characteristics & LookupPolicy.IPV4_FIRST) != 0);
            }

            return pinned.stream();
        }

        private static Stream<InetAddress> reorderByAddressFamily(List<InetAddress> pinned, boolean ipv4First) {
            List<InetAddress> primary = new ArrayList<>(pinned.size());
            List<InetAddress> secondary = new ArrayList<>(pinned.size());
            for (InetAddress addr : pinned) {
                if ((addr instanceof Inet4Address) == ipv4First) {
                    primary.add(addr);
                } else {
                    secondary.add(addr);
                }
            }
            primary.addAll(secondary);
            return primary.stream();
        }
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class PinnedRestAssuredFilter implements OrderedFilter {
        @Override
        public int getOrder() {
            return OrderedFilter.HIGHEST_PRECEDENCE;
        }

        @Override
        public Response filter(
                FilterableRequestSpecification requestSpec,
                FilterableResponseSpecification responseSpec,
                FilterContext ctx) {
            PinnedScopeImpl activeScope = CURRENT_SCOPE.get();
            if (activeScope == null || activeScope.isClosed()) {
                return ctx.next(requestSpec, responseSpec);
            }

            validateValidatorRequestUri(activeScope.target(), requestSpec.getURI());
            configurePinnedRequest(requestSpec, activeScope);
            return ctx.next(requestSpec, responseSpec);
        }

        static void configurePinnedRequest(
                FilterableRequestSpecification requestSpec,
                PinnedScopeImpl activeScope) {
            RestAssuredConfig existingConfig = requestSpec.getConfig() != null
                    ? requestSpec.getConfig()
                    : RestAssured.config();
            rejectUnsupportedRequestFeatures(requestSpec, existingConfig);
            org.apache.http.client.HttpClient rawClient = requestSpec.getHttpClient();
            if (!(rawClient instanceof AbstractHttpClient abstractClient)) {
                throw new IllegalStateException(
                        "Unsupported RestAssured HttpClient implementation: "
                                + (rawClient != null ? rawClient.getClass().getName() : "null"));
            }

            HttpClientConfig existingHttpCfg = existingConfig.getHttpClientConfig();
            boolean clientReused = existingHttpCfg != null
                    && existingHttpCfg.isConfiguredToReuseTheSameHttpClientInstance();

            DnsResolver pinnedResolver = dnsResolverFor(activeScope.target());
            PinnedPlainSocketFactory plainFactory = new PinnedPlainSocketFactory(pinnedResolver);
            PinnedStrictHttpsSocketFactory httpsFactory = new PinnedStrictHttpsSocketFactory(pinnedResolver);

            SchemeRegistry schemeRegistry = abstractClient.getConnectionManager().getSchemeRegistry();
            schemeRegistry.register(new Scheme(SCHEME_HTTP, 80, plainFactory));
            schemeRegistry.register(new Scheme(SCHEME_HTTPS, 443, httpsFactory));

            abstractClient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false));
            abstractClient.setRedirectStrategy(new SafePinnedRedirectStrategy(activeScope.target()));
            if (!clientReused) {
                abstractClient.setReuseStrategy(NoConnectionReuseStrategy.INSTANCE);
                activeScope.trackConnectionManager(abstractClient.getConnectionManager());
            }

            int connectTimeoutMs = resolveConnectTimeoutMs();
            int socketTimeoutMs = resolveSocketTimeoutMs();
            long connManagerTimeoutMs = resolveConnectionManagerTimeoutMs();

            HttpParams params = abstractClient.getParams();
            HttpConnectionParams.setConnectionTimeout(params, connectTimeoutMs);
            HttpConnectionParams.setSoTimeout(params, socketTimeoutMs);
            HttpClientParams.setConnectionManagerTimeout(params, connManagerTimeoutMs);
            HttpClientParams.setCookiePolicy(params, CookiePolicy.IGNORE_COOKIES);

            HttpClientConfig baseHttpCfg = existingHttpCfg != null ? existingHttpCfg : HttpClientConfig.httpClientConfig();
            HttpClientConfig pinnedHttpCfg = baseHttpCfg
                    .setParam("http.connection.timeout", connectTimeoutMs)
                    .setParam("http.socket.timeout", socketTimeoutMs)
                    .setParam("http.connection-manager.timeout", connManagerTimeoutMs);
            RedirectConfig pinnedRedirectCfg = capRedirectConfig(existingConfig.getRedirectConfig());
            SSLConfig pinnedSslCfg = SSLConfig.sslConfig().sslSocketFactory(httpsFactory).strictHostnames();

            requestSpec.config(existingConfig
                    .redirect(pinnedRedirectCfg)
                    .httpClient(pinnedHttpCfg)
                    .sslConfig(pinnedSslCfg));
        }

        private static void rejectUnsupportedRequestFeatures(
                FilterableRequestSpecification requestSpec,
                RestAssuredConfig existingConfig) {
            if (requestSpec.getAuthenticationScheme() instanceof CertAuthScheme) {
                shutdownRejectedClientIfEphemeral(requestSpec, existingConfig);
                throw new IllegalStateException(
                        "Certificate authentication scheme is not supported in pinned SCIM validation requests");
            }
            if (existingConfig.getSSLConfig() != null && existingConfig.getSSLConfig().isUserConfigured()) {
                shutdownRejectedClientIfEphemeral(requestSpec, existingConfig);
                throw new IllegalStateException(
                        "Custom or relaxed SSL configuration is not supported in pinned SCIM validation requests");
            }
            if (requestSpec.getProxySpecification() != null) {
                shutdownRejectedClientIfEphemeral(requestSpec, existingConfig);
                throw new IllegalStateException(
                        "Outbound proxy specification is not supported in pinned SCIM validation requests");
            }
        }

        private static void shutdownRejectedClientIfEphemeral(
                FilterableRequestSpecification requestSpec,
                RestAssuredConfig existingConfig) {
            HttpClientConfig httpCfg = existingConfig.getHttpClientConfig();
            boolean reused = httpCfg != null && httpCfg.isConfiguredToReuseTheSameHttpClientInstance();
            org.apache.http.client.HttpClient client = requestSpec.getHttpClient();
            if (!reused && client != null && client.getConnectionManager() != null) {
                client.getConnectionManager().shutdown();
            }
        }

        static RedirectConfig capRedirectConfig(RedirectConfig existingRedirect) {
            if (existingRedirect == null) {
                return RedirectConfig.redirectConfig().maxRedirects(SafePinnedRedirectStrategy.DEFAULT_MAX_REDIRECTS);
            }
            if (existingRedirect.followsRedirects()
                    && existingRedirect.maxRedirects() > SafePinnedRedirectStrategy.DEFAULT_MAX_REDIRECTS) {
                return existingRedirect.maxRedirects(SafePinnedRedirectStrategy.DEFAULT_MAX_REDIRECTS);
            }
            return existingRedirect;
        }
    }
}
