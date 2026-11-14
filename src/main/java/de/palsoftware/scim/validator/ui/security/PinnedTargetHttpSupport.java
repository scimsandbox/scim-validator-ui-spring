package de.palsoftware.scim.validator.ui.security;

import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.filter.OrderedFilter;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolver.LookupPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/**
 * Pins outbound HTTP client connections (Apache HttpClient 4.5, RestAssured legacy HttpClient,
 * and JDK {@link java.net.http.HttpClient} via {@link PinnedInetAddressResolverProvider}) to the
 * exact {@link InetAddress} list validated by {@link TargetUrlPolicy#resolve(String)}, preventing
 * DNS-rebinding (TOCTOU) attacks while preserving the original hostname for the HTTP {@code Host}
 * header, TLS SNI, and RFC 6125 X.509 certificate hostname verification.
 */
public final class PinnedTargetHttpSupport {

    static final int DEFAULT_REST_ASSURED_CONNECT_TIMEOUT_MS = 10_000;
    static final int DEFAULT_REST_ASSURED_SOCKET_TIMEOUT_MS = 60_000;
    static final long DEFAULT_REST_ASSURED_CONN_MANAGER_TIMEOUT_MS = 10_000L;
    private static final int POOL_DEFAULT_MAX_PER_ROUTE = 16;
    private static final int POOL_MAX_TOTAL = 32;

    private static final ConcurrentHashMap<String, CopyOnWriteArrayList<PinRegistration>> ACTIVE_PINS =
            new ConcurrentHashMap<>();
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<PinnedScopeImpl> CURRENT_SCOPE = new ThreadLocal<>();
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<Boolean> BYPASS_PIN = new ThreadLocal<>();
    private static final OrderedFilter REST_ASSURED_FILTER = new PinnedRestAssuredFilter();

    static {
        java.security.Security.setProperty("networkaddress.cache.ttl", "0");
        java.security.Security.setProperty("networkaddress.cache.negative.ttl", "0");
        PinnedInetAddressResolverProvider.resolverHook = PinnedTargetHttpSupport::lookupWithActivePins;
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
        PinnedInetAddressResolverProvider.builtinResolver =
                Objects.requireNonNull(resolver, "InetAddressResolver must not be null");
    }

    static InetAddressResolver currentBuiltinResolver() {
        return PinnedInetAddressResolverProvider.builtinResolver;
    }

    /**
     * Ensures the JVM {@link java.util.ServiceLoader} has initialized {@link PinnedInetAddressResolverProvider}
     * under the current context {@link ClassLoader} (critical for Spring Boot's {@code LaunchedClassLoader}).
     */
    public static void initializeJvmDnsPinning() {
        PinnedInetAddressResolverProvider.resolverHook = PinnedTargetHttpSupport::lookupWithActivePins;
        if (PinnedInetAddressResolverProvider.builtinResolver != null) {
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
        InetAddressResolver resolver = PinnedInetAddressResolverProvider.builtinResolver;
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
        Objects.requireNonNull(target, "ResolvedTarget must not be null");
        return new PinnedDnsResolver(target);
    }

    public static CloseableHttpClient createPinnedHttpClient(
            TargetUrlPolicy.ResolvedTarget target,
            int connectTimeoutMs,
            int socketTimeoutMs) {
        DnsResolver dnsResolver = dnsResolverFor(target);
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSystemSocketFactory())
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
        Objects.requireNonNull(target, "ResolvedTarget must not be null");
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

    public static String normalizeDnsHost(String rawHost) {
        if (rawHost == null) {
            return "";
        }
        String host = rawHost.trim();
        if (host.isEmpty()) {
            return "";
        }
        boolean bracketed = false;
        if (host.startsWith("[") && host.endsWith("]") && host.length() > 2) {
            host = host.substring(1, host.length() - 1);
            bracketed = true;
        }
        if (!bracketed) {
            while (host.endsWith(".")) {
                host = host.substring(0, host.length() - 1);
            }
            if (containsNonAscii(host)) {
                try {
                    host = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED);
                } catch (IllegalArgumentException ignored) {
                    // Keep lowercased host if Punycode conversion rejects input
                }
            }
        }
        host = host.toLowerCase(Locale.ROOT);
        if (!host.isEmpty() && !host.contains("%") && looksLikeIpLiteral(host)) {
            try {
                return InetAddress.ofLiteral(host).getHostAddress().toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException ignored) {
                // Not a valid IP literal; return normalized string as-is
            }
        }
        return host;
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
        for (String candidate : new String[]{sysPropValue, envValue}) {
            if (candidate != null && !candidate.isBlank()) {
                try {
                    long parsed = Long.parseLong(candidate.trim());
                    if (parsed > 0) {
                        return parsed;
                    }
                } catch (NumberFormatException ignored) {
                    // Fall through to next source or default
                }
            }
        }
        return defaultValue;
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static AbstractHttpClient createLegacyPinnedHttpClient(DnsResolver pinnedDnsResolver) {
        Objects.requireNonNull(pinnedDnsResolver, "Pinned DnsResolver must not be null");

        StrictHttpsSocketFactory strictSslSocketFactory = new StrictHttpsSocketFactory();

        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
        schemeRegistry.register(new Scheme("https", 443, strictSslSocketFactory));

        PoolingClientConnectionManager connectionManager =
                new PoolingClientConnectionManager(schemeRegistry, pinnedDnsResolver);
        connectionManager.setDefaultMaxPerRoute(POOL_DEFAULT_MAX_PER_ROUTE);
        connectionManager.setMaxTotal(POOL_MAX_TOTAL);

        PinnedLegacyHttpClient client = new PinnedLegacyHttpClient(connectionManager);
        client.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false));
        HttpParams params = client.getParams();
        HttpConnectionParams.setConnectionTimeout(params, resolveConnectTimeoutMs());
        HttpConnectionParams.setSoTimeout(params, resolveSocketTimeoutMs());
        HttpClientParams.setConnectionManagerTimeout(params, resolveConnectionManagerTimeoutMs());
        HttpClientParams.setRedirecting(params, false);
        HttpClientParams.setCookiePolicy(params, CookiePolicy.IGNORE_COOKIES);
        return client;
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class StrictHttpsSocketFactory extends SSLSocketFactory {
        StrictHttpsSocketFactory() {
            super(
                    (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault(),
                    SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
        }

        @Override
        protected void prepareSocket(SSLSocket socket) throws IOException {
            SSLParameters sslParams = socket.getSSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(sslParams);
        }
    }

    @SuppressWarnings({"deprecation", "java:S1874"})
    static final class PinnedLegacyHttpClient extends DefaultHttpClient {
        PinnedLegacyHttpClient(ClientConnectionManager conman) {
            super(conman);
        }
    }

    @SuppressWarnings({"deprecation", "java:S1874", "java:S3011"})
    static void replaceRestAssuredHttpClient(
            FilterableRequestSpecification requestSpec,
            AbstractHttpClient pinnedClient) {
        org.apache.http.client.HttpClient existing = requestSpec.getHttpClient();
        if (existing == pinnedClient) {
            return;
        }
        Class<?> type = requestSpec.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField("httpClient");
                field.setAccessible(true);
                field.set(requestSpec, pinnedClient);
                if (existing != null && !(existing instanceof PinnedLegacyHttpClient)) {
                    existing.getConnectionManager().shutdown();
                }
                return;
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            } catch (ReflectiveOperationException ex) {
                throw new IllegalStateException("Failed to install pinned HttpClient on RestAssured request", ex);
            }
        }
        throw new IllegalStateException(
                "Unsupported RestAssured RequestSpecification implementation: " + requestSpec.getClass().getName());
    }

    static final class PinnedScopeImpl implements PinnedScope {
        private final TargetUrlPolicy.ResolvedTarget target;
        private final String normalizedHost;
        private final PinRegistration registration;
        private final PinnedScopeImpl previous;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private volatile AbstractHttpClient restAssuredClient;

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

        AbstractHttpClient getOrCreateRestAssuredClient() {
            if (closed.get()) {
                throw new IllegalStateException("Pinned HTTP scope is already closed");
            }
            AbstractHttpClient client = restAssuredClient;
            if (client != null) {
                return client;
            }
            synchronized (this) {
                if (closed.get()) {
                    throw new IllegalStateException("Pinned HTTP scope is already closed");
                }
                if (restAssuredClient == null) {
                    restAssuredClient = createLegacyPinnedHttpClient(dnsResolverFor(target));
                }
                return restAssuredClient;
            }
        }

        @Override
        @SuppressWarnings({"deprecation", "java:S1874"})
        public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            if (CURRENT_SCOPE.get() == this) {
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
            ACTIVE_PINS.computeIfPresent(normalizedHost, (k, list) -> {
                list.remove(registration);
                return list.isEmpty() ? null : list;
            });
            AbstractHttpClient client;
            synchronized (this) {
                client = restAssuredClient;
                restAssuredClient = null;
            }
            if (client != null) {
                client.getConnectionManager().shutdown();
            }
        }
    }

    static final class PinnedDnsResolver implements DnsResolver {
        private final String canonicalTargetHost;
        private final List<InetAddress> addresses;

        PinnedDnsResolver(TargetUrlPolicy.ResolvedTarget target) {
            Objects.requireNonNull(target, "ResolvedTarget must not be null");
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
                boolean ipv4First = (characteristics & LookupPolicy.IPV4_FIRST) != 0;
                List<InetAddress> primary = new ArrayList<>(pinned.size());
                List<InetAddress> secondary = new ArrayList<>(pinned.size());
                for (InetAddress addr : pinned) {
                    boolean isV4 = addr instanceof Inet4Address;
                    if (isV4 == ipv4First) {
                        primary.add(addr);
                    } else {
                        secondary.add(addr);
                    }
                }
                primary.addAll(secondary);
                return primary.stream();
            }

            return pinned.stream();
        }
    }

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

            TargetUrlPolicy.DEFAULT_STRICT.validateSameOriginUri(activeScope.target(), requestSpec.getURI());

            RestAssuredConfig existingConfig = requestSpec.getConfig() != null
                    ? requestSpec.getConfig()
                    : RestAssured.config();
            AbstractHttpClient scopeClient = activeScope.getOrCreateRestAssuredClient();

            RestAssuredConfig pinnedConfig = existingConfig
                    .redirect(RedirectConfig.redirectConfig().followRedirects(false))
                    .httpClient(HttpClientConfig.httpClientConfig()
                            .reuseHttpClientInstance()
                            .setParam("http.connection.timeout", resolveConnectTimeoutMs())
                            .setParam("http.socket.timeout", resolveSocketTimeoutMs())
                            .setParam("http.connection-manager.timeout", resolveConnectionManagerTimeoutMs())
                            .httpClientFactory(() -> scopeClient));

            requestSpec.config(pinnedConfig);
            replaceRestAssuredHttpClient(requestSpec, scopeClient);
            return ctx.next(requestSpec, responseSpec);
        }
    }
}
