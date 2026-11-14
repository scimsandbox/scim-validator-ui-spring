package de.palsoftware.scim.validator.ui.security;

import com.sun.net.httpserver.HttpServer;
import io.restassured.RestAssured;
import io.restassured.filter.Filter;
import io.restassured.response.Response;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.HttpHost;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolver.LookupPolicy;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PinnedTargetHttpSupportTest {

    private static HttpServer server;
    private static int port;
    private static final AtomicReference<String> lastHostHeader = new AtomicReference<>();

    @BeforeAll
    static void startServer() throws IOException {
        PinnedTargetHttpSupport.initializeJvmDnsPinning();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();

        server.createContext("/test", exchange -> {
            lastHostHeader.set(exchange.getRequestHeaders().getFirst("Host"));
            byte[] body = "{\"status\":\"pinned-ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", "http://169.254.169.254/latest/meta-data/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        server.start();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void restAssuredPinningReusesPooledClientShutsDownOnCloseAndBlocksRedirectsAndUnpinnedOrigins() throws Exception {
        String baseUri = "http://rebind.example.test:" + port;
        TargetUrlPolicy.ResolvedTarget pinnedTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create(baseUri),
                "rebind.example.test",
                List.of(InetAddress.getByName("127.0.0.1")));

        PinnedTargetHttpSupport.ensureRestAssuredFilterInstalled();
        long filterCountBefore = RestAssured.filters().stream()
                .filter(Filter.class::isInstance)
                .filter(f -> f instanceof PinnedTargetHttpSupport.PinnedRestAssuredFilter)
                .count();
        PinnedTargetHttpSupport.ensureRestAssuredFilterInstalled();
        long filterCountAfter = RestAssured.filters().stream()
                .filter(Filter.class::isInstance)
                .filter(f -> f instanceof PinnedTargetHttpSupport.PinnedRestAssuredFilter)
                .count();
        assertThat(filterCountBefore).isEqualTo(1);
        assertThat(filterCountAfter).isEqualTo(1);

        assertThatThrownBy(() -> RestAssured.given().baseUri(baseUri).get("/test"))
                .isInstanceOf(UnknownHostException.class);

        PinnedTargetHttpSupport.PinnedScopeImpl capturedScopeImpl;
        org.apache.http.impl.client.AbstractHttpClient pooledScopeClient;

        try (var scope = PinnedTargetHttpSupport.pin(pinnedTarget)) {
            capturedScopeImpl = (PinnedTargetHttpSupport.PinnedScopeImpl) scope;
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(pinnedTarget);

            // First and second requests reuse the exact same pooled client without premature shutdown
            Response okResponse1 = RestAssured.given().baseUri(baseUri).get("/test");
            pooledScopeClient = capturedScopeImpl.getOrCreateRestAssuredClient();
            Response okResponse2 = RestAssured.given().baseUri(baseUri).get("/test");
            assertThat(capturedScopeImpl.getOrCreateRestAssuredClient()).isSameAs(pooledScopeClient);

            assertThat(okResponse1.statusCode()).isEqualTo(200);
            assertThat(okResponse2.statusCode()).isEqualTo(200);
            assertThat(okResponse2.body().asString()).contains("pinned-ok");
            assertThat(lastHostHeader.get()).isEqualTo("rebind.example.test:" + port);

            // Verify PoolingClientConnectionManager, 0 retries, IGNORE_COOKIES, and strict HTTPS endpoint verification
            assertThat(pooledScopeClient).isInstanceOf(PinnedTargetHttpSupport.PinnedLegacyHttpClient.class);
            assertThat(pooledScopeClient.getConnectionManager()).isInstanceOf(PoolingClientConnectionManager.class);
            PoolingClientConnectionManager pool = (PoolingClientConnectionManager) pooledScopeClient.getConnectionManager();
            assertThat(pool.getDefaultMaxPerRoute()).isEqualTo(16);
            assertThat(pool.getMaxTotal()).isEqualTo(32);

            DefaultHttpRequestRetryHandler retryHandler =
                    (DefaultHttpRequestRetryHandler) pooledScopeClient.getHttpRequestRetryHandler();
            assertThat(retryHandler.getRetryCount()).isZero();
            assertThat(retryHandler.isRequestSentRetryEnabled()).isFalse();
            assertThat(HttpClientParams.getCookiePolicy(pooledScopeClient.getParams()))
                    .isEqualTo(CookiePolicy.IGNORE_COOKIES);

            PinnedTargetHttpSupport.StrictHttpsSocketFactory httpsFactory =
                    (PinnedTargetHttpSupport.StrictHttpsSocketFactory) pool.getSchemeRegistry()
                            .getScheme("https")
                            .getSchemeSocketFactory();
            assertThat(httpsFactory.getHostnameVerifier()).isSameAs(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
            try (SSLSocket sslSocket = (SSLSocket) javax.net.ssl.SSLSocketFactory.getDefault().createSocket()) {
                httpsFactory.prepareSocket(sslSocket);
                assertThat(sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm()).isEqualTo("HTTPS");
            }

            // Redirects are NOT followed even when caller config enables redirects
            Response redirectResponse = RestAssured.given()
                    .config(RestAssured.config().redirect(
                            io.restassured.config.RedirectConfig.redirectConfig().followRedirects(true)))
                    .baseUri(baseUri)
                    .get("/redirect");
            assertThat(redirectResponse.statusCode()).isEqualTo(302);
            assertThat(redirectResponse.getHeader("Location")).isEqualTo("http://169.254.169.254/latest/meta-data/");

            // Requests to any unpinned host or port are blocked before opening a socket
            assertThatThrownBy(() -> RestAssured.given()
                    .baseUri("http://other.example.test:" + port)
                    .get("/test"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("configured target origin");

            // Nested pin scope restores previous target when closed
            TargetUrlPolicy.ResolvedTarget nestedTarget = new TargetUrlPolicy.ResolvedTarget(
                    URI.create("https://nested.example.test:8443"),
                    "nested.example.test",
                    List.of(InetAddress.getByName("93.184.216.34")));
            try (var nested = PinnedTargetHttpSupport.pin(nestedTarget)) {
                assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(nestedTarget);
            }
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(pinnedTarget);
        }

        // Calling close() a second time is idempotent, and the scope's connection pool is shut down
        capturedScopeImpl.close();
        assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isNull();
        HttpRoute route = new HttpRoute(new HttpHost("rebind.example.test", port));
        assertThatThrownBy(() -> pooledScopeClient.getConnectionManager().requestConnection(route, null))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void jdkHttpClientUsesPinnedInetAddressResolverAcrossAsyncWorkerThreadsAndReferenceCountsOverlappingPins() throws Exception {
        assertThat(PinnedTargetHttpSupport.currentBuiltinResolver()).isNotNull();

        String url = "http://rebind.example.test:" + port + "/test";
        TargetUrlPolicy.ResolvedTarget pinnedTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("http://rebind.example.test:" + port),
                "rebind.example.test",
                List.of(InetAddress.getByName("127.0.0.1")));

        // Pre-started worker pool (created before pin() so InheritableThreadLocal is NOT inherited, mirroring Rfc9967AsyncSpec)
        ExecutorService preStartedPool = Executors.newSingleThreadExecutor();
        preStartedPool.submit(() -> null).get(5, TimeUnit.SECONDS);

        HttpClient jdkClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .build();

        try {
            // Unpinned: rebind.example.test fails resolution
            assertThatThrownBy(() -> jdkClient.send(request, HttpResponse.BodyHandlers.ofString()))
                    .isInstanceOf(IOException.class);

            var scope1 = PinnedTargetHttpSupport.pin(pinnedTarget);
            var scope2 = PinnedTargetHttpSupport.pin(pinnedTarget);
            try {
                // Calling thread resolves via active pin
                HttpResponse<String> resp1 = jdkClient.send(request, HttpResponse.BodyHandlers.ofString());
                assertThat(resp1.statusCode()).isEqualTo(200);
                assertThat(resp1.body()).contains("pinned-ok");
                assertThat(lastHostHeader.get()).startsWith("rebind.example.test");

                // Independent async worker thread resolves via active pin
                HttpResponse<String> asyncResp = preStartedPool.submit(
                        () -> jdkClient.send(request, HttpResponse.BodyHandlers.ofString()))
                        .get(5, TimeUnit.SECONDS);
                assertThat(asyncResp.statusCode()).isEqualTo(200);
                assertThat(asyncResp.body()).contains("pinned-ok");

                // CRITICAL: resolveUnpinned bypasses active pins and InetAddress.cache
                assertThatThrownBy(() -> PinnedTargetHttpSupport.resolveUnpinned("rebind.example.test"))
                        .isInstanceOf(UnknownHostException.class);
                assertThat(PinnedTargetHttpSupport.resolveUnpinned("localhost")).isNotEmpty();

                // Closing scope1 leaves scope2's registration active for concurrent run
                scope1.close();
                HttpResponse<String> stillPinnedResp = preStartedPool.submit(
                        () -> jdkClient.send(request, HttpResponse.BodyHandlers.ofString()))
                        .get(5, TimeUnit.SECONDS);
                assertThat(stillPinnedResp.statusCode()).isEqualTo(200);
            } finally {
                scope2.close();
                scope1.close();
            }

            // Once all overlapping scopes close, rebind.example.test is unpinned again
            assertThatThrownBy(() -> jdkClient.send(request, HttpResponse.BodyHandlers.ofString()))
                    .isInstanceOf(IOException.class);
        } finally {
            preStartedPool.shutdownNow();
        }
    }

    @Test
    void pinnedInetAddressResolverProviderAndLookupPolicyFilteringWork() throws Exception {
        InetAddress v4 = InetAddress.getByName("93.184.216.34");
        InetAddress v6 = InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946");

        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(List.of(v4, v6), null).toList())
                .containsExactly(v4, v6);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV4)).toList())
                .containsExactly(v4);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV6)).toList())
                .containsExactly(v6);
        // Single-stack fallback when requested family is absent in pinned set
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v4), LookupPolicy.of(LookupPolicy.IPV6)).toList())
                .containsExactly(v4);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v6, v4), LookupPolicy.of(LookupPolicy.IPV4 | LookupPolicy.IPV6 | LookupPolicy.IPV4_FIRST)).toList())
                .containsExactly(v4, v6);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV4 | LookupPolicy.IPV6 | LookupPolicy.IPV6_FIRST)).toList())
                .containsExactly(v6, v4);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV4 | LookupPolicy.IPV6)).toList())
                .containsExactly(v4, v6);

        InetAddressResolver existingBuiltin = PinnedTargetHttpSupport.currentBuiltinResolver();
        try {
            PinnedInetAddressResolverProvider provider = new PinnedInetAddressResolverProvider();
            assertThat(provider.name()).isEqualTo("scim-validator-pinned-dns-resolver");

            InetAddressResolver mockBuiltin = org.mockito.Mockito.mock(InetAddressResolver.class);
            org.mockito.Mockito.when(mockBuiltin.lookupByAddress(v4.getAddress())).thenReturn("example.com");
            org.mockito.Mockito.when(mockBuiltin.lookupByName(org.mockito.Mockito.eq("empty.example.test"), org.mockito.Mockito.any()))
                    .thenAnswer(inv -> Stream.empty());

            PinnedTargetHttpSupport.installBuiltinResolver(mockBuiltin);
            PinnedTargetHttpSupport.PinnedInetAddressResolver resolver =
                    new PinnedTargetHttpSupport.PinnedInetAddressResolver(mockBuiltin);
            assertThat(resolver.lookupByAddress(v4.getAddress())).isEqualTo("example.com");
            assertThat(resolver.lookupByName("empty.example.test", LookupPolicy.of(LookupPolicy.IPV4)).toList()).isEmpty();
            assertThatThrownBy(() -> PinnedTargetHttpSupport.resolveUnpinned("empty.example.test"))
                    .isInstanceOf(UnknownHostException.class);

            // Cover fallback path when builtinResolver is null (e.g. before SPI initialization)
            PinnedInetAddressResolverProvider.builtinResolver = null;
            assertThat(PinnedTargetHttpSupport.resolveUnpinned("localhost")).isNotEmpty();
        } finally {
            if (existingBuiltin != null) {
                PinnedTargetHttpSupport.installBuiltinResolver(existingBuiltin);
            }
        }
    }

    @Test
    void pinnedDnsResolverNormalizesBracketsIpv6RepresentationsPunycodeAndRejectsUnpinnedHosts() throws Exception {
        InetAddress pinnedIpv6 = InetAddress.getByName("2606:2800:220:1::1");
        TargetUrlPolicy.ResolvedTarget ipv6Target = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://[2606:2800:0220:0001::1]/scim/v2"),
                "2606:2800:0220:0001::1",
                List.of(pinnedIpv6));
        DnsResolver ipv6Resolver = PinnedTargetHttpSupport.dnsResolverFor(ipv6Target);

        assertThat(ipv6Resolver.resolve("[2606:2800:220:1::1]")).containsExactly(pinnedIpv6);
        assertThat(ipv6Resolver.resolve("2606:2800:0220:0001:0:0:0:1")).containsExactly(pinnedIpv6);
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[0:0:0:0:0:0:0:1]"))
                .isEqualTo(PinnedTargetHttpSupport.normalizeDnsHost("[::1]"));
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("93.184.216.34"))
                .isEqualTo("93.184.216.34");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("999.999.999.999"))
                .isEqualTo("999.999.999.999");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[fe80::1%eth0]"))
                .isEqualTo("fe80::1%eth0");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("/not-a-host"))
                .isEqualTo("/not-a-host");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("1invalid.example.com"))
                .isEqualTo("1invalid.example.com");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("bücher.example.com."))
                .isEqualTo("xn--bcher-kva.example.com");

        InetAddress pinnedIpv4 = InetAddress.getByName("93.184.216.34");
        TargetUrlPolicy.ResolvedTarget domainTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com/scim/v2"),
                "scim.example.com",
                List.of(pinnedIpv4));
        DnsResolver domainResolver = PinnedTargetHttpSupport.dnsResolverFor(domainTarget);

        assertThat(domainResolver.resolve("SCIM.EXAMPLE.COM.")).containsExactly(pinnedIpv4);
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[]")).isEqualTo("[]");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[unclosed")).isEqualTo("[unclosed");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost(null)).isEmpty();
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("   ")).isEmpty();
        assertThatThrownBy(() -> domainResolver.resolve("attacker.example.com"))
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("Blocked outbound connection to unpinned host");
        assertThatThrownBy(() -> domainResolver.resolve(null))
                .isInstanceOf(UnknownHostException.class);
        assertThatThrownBy(() -> domainResolver.resolve("   "))
                .isInstanceOf(UnknownHostException.class);
    }

    @Test
    void replaceRestAssuredHttpClientAndFilterEdgeBranchesAreCovered() throws Exception {
        TargetUrlPolicy.ResolvedTarget domainTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("http://rebind.example.test:" + port),
                "rebind.example.test",
                List.of(InetAddress.getByName("127.0.0.1")));
        DnsResolver resolver = PinnedTargetHttpSupport.dnsResolverFor(domainTarget);
        var pinnedClient = PinnedTargetHttpSupport.createLegacyPinnedHttpClient(resolver);

        io.restassured.specification.FilterableRequestSpecification sameClientSpec =
                org.mockito.Mockito.mock(io.restassured.specification.FilterableRequestSpecification.class);
        org.mockito.Mockito.when(sameClientSpec.getHttpClient()).thenReturn(pinnedClient);
        PinnedTargetHttpSupport.replaceRestAssuredHttpClient(sameClientSpec, pinnedClient);

        io.restassured.specification.FilterableRequestSpecification unsupportedSpec =
                org.mockito.Mockito.mock(io.restassured.specification.FilterableRequestSpecification.class);
        org.mockito.Mockito.when(unsupportedSpec.getHttpClient()).thenReturn(null);
        assertThatThrownBy(() -> PinnedTargetHttpSupport.replaceRestAssuredHttpClient(unsupportedSpec, pinnedClient))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unsupported RestAssured RequestSpecification");

        var filter = new PinnedTargetHttpSupport.PinnedRestAssuredFilter();
        assertThat(filter.getOrder()).isEqualTo(io.restassured.filter.OrderedFilter.HIGHEST_PRECEDENCE);

        io.restassured.specification.FilterableRequestSpecification realSpec =
                (io.restassured.specification.FilterableRequestSpecification) RestAssured.given().baseUri("http://rebind.example.test:" + port);
        io.restassured.specification.FilterableResponseSpecification realRespSpec =
                (io.restassured.specification.FilterableResponseSpecification) RestAssured.expect();
        io.restassured.filter.FilterContext filterCtx = org.mockito.Mockito.mock(io.restassured.filter.FilterContext.class);
        org.mockito.Mockito.when(filterCtx.next(realSpec, realRespSpec)).thenAnswer(inv -> {
            io.restassured.specification.FilterableRequestSpecification req = inv.getArgument(0);
            var created = req.getConfig().getHttpClientConfig().httpClientInstance();
            assertThat(created).isInstanceOf(PinnedTargetHttpSupport.PinnedLegacyHttpClient.class);
            return org.mockito.Mockito.mock(Response.class);
        });

        PinnedTargetHttpSupport.replaceRestAssuredHttpClient(realSpec, pinnedClient);
        // Outside pin scope, filter passes through directly to ctx.next(...)
        org.mockito.Mockito.when(filterCtx.next(unsupportedSpec, realRespSpec))
                .thenReturn(org.mockito.Mockito.mock(Response.class));
        assertThat(filter.filter(unsupportedSpec, realRespSpec, filterCtx)).isNotNull();

        try (var scope = PinnedTargetHttpSupport.pin(domainTarget)) {
            Response res = filter.filter(realSpec, realRespSpec, filterCtx);
            assertThat(res).isNotNull();
        }
        pinnedClient.getConnectionManager().shutdown();
    }

    @Test
    void outOfOrderScopeCloseClosedClientGuardNonInheritableThreadLocalAndTimeoutDefaultsAreEnforced() throws Exception {
        TargetUrlPolicy.ResolvedTarget t1 = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://t1.example.test:8443"),
                "t1.example.test",
                List.of(InetAddress.getByName("93.184.216.34")));
        TargetUrlPolicy.ResolvedTarget t2 = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://t2.example.test:8443"),
                "t2.example.test",
                List.of(InetAddress.getByName("93.184.216.34")));
        TargetUrlPolicy.ResolvedTarget t3 = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://t3.example.test:8443"),
                "t3.example.test",
                List.of(InetAddress.getByName("93.184.216.34")));

        // 1. Out-of-order close (scope1 closed while scope2 open -> scope2 close clears CURRENT_SCOPE completely)
        var scope1 = PinnedTargetHttpSupport.pin(t1);
        var scope2 = PinnedTargetHttpSupport.pin(t2);
        try {
            // Child thread does NOT inherit CURRENT_SCOPE (plain ThreadLocal, not InheritableThreadLocal)
            AtomicReference<TargetUrlPolicy.ResolvedTarget> childScopeTarget = new AtomicReference<>();
            Thread child = new Thread(() -> childScopeTarget.set(PinnedTargetHttpSupport.currentPinnedTarget()));
            child.start();
            child.join(3_000);
            assertThat(childScopeTarget.get()).isNull();

            scope1.close();
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(t2);
        } finally {
            scope2.close();
            scope1.close();
        }
        assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isNull();
        assertThat(PinnedTargetHttpSupport.currentScopeForTesting()).isNull();

        // 2. 3-level nested close skipping closed middle scope restores outermost live ancestor
        var outer = PinnedTargetHttpSupport.pin(t1);
        var middle = PinnedTargetHttpSupport.pin(t2);
        var inner = PinnedTargetHttpSupport.pin(t3);
        try {
            middle.close();
            inner.close();
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(t1);
        } finally {
            outer.close();
            middle.close();
            inner.close();
        }
        assertThat(PinnedTargetHttpSupport.currentScopeForTesting()).isNull();

        // 3. Calling getOrCreateRestAssuredClient() on a closed scope fails without leaking a connection pool
        PinnedTargetHttpSupport.PinnedScopeImpl closedScope = (PinnedTargetHttpSupport.PinnedScopeImpl) outer;
        assertThatThrownBy(closedScope::getOrCreateRestAssuredClient)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already closed");

        // 4. Default & system-property-overridden connect, socket, and connection-manager timeouts match ScimBaseSpec
        DnsResolver resolver = PinnedTargetHttpSupport.dnsResolverFor(t1);
        var defaultClient = PinnedTargetHttpSupport.createLegacyPinnedHttpClient(resolver);
        try {
            org.apache.http.params.HttpParams defaultParams = defaultClient.getParams();
            assertThat(org.apache.http.params.HttpConnectionParams.getConnectionTimeout(defaultParams)).isEqualTo(10_000);
            assertThat(org.apache.http.params.HttpConnectionParams.getSoTimeout(defaultParams)).isEqualTo(60_000);
            assertThat(HttpClientParams.getConnectionManagerTimeout(defaultParams)).isEqualTo(10_000L);
        } finally {
            defaultClient.getConnectionManager().shutdown();
        }

        String prevConnect = System.getProperty("scim.http.connectTimeoutMs");
        String prevSocket = System.getProperty("scim.http.socketTimeoutMs");
        String prevConnMgr = System.getProperty("scim.http.connectionManagerTimeoutMs");
        try {
            System.setProperty("scim.http.connectTimeoutMs", "12345");
            System.setProperty("scim.http.socketTimeoutMs", "54321");
            System.setProperty("scim.http.connectionManagerTimeoutMs", "23456");

            var customClient = PinnedTargetHttpSupport.createLegacyPinnedHttpClient(resolver);
            try {
                org.apache.http.params.HttpParams customParams = customClient.getParams();
                assertThat(org.apache.http.params.HttpConnectionParams.getConnectionTimeout(customParams)).isEqualTo(12_345);
                assertThat(org.apache.http.params.HttpConnectionParams.getSoTimeout(customParams)).isEqualTo(54_321);
                assertThat(HttpClientParams.getConnectionManagerTimeout(customParams)).isEqualTo(23_456L);
            } finally {
                customClient.getConnectionManager().shutdown();
            }

            var filter = new PinnedTargetHttpSupport.PinnedRestAssuredFilter();
            io.restassured.specification.FilterableRequestSpecification reqSpec =
                    (io.restassured.specification.FilterableRequestSpecification) RestAssured.given().baseUri("https://t1.example.test:8443");
            io.restassured.specification.FilterableResponseSpecification respSpec =
                    (io.restassured.specification.FilterableResponseSpecification) RestAssured.expect();
            io.restassured.filter.FilterContext ctx = org.mockito.Mockito.mock(io.restassured.filter.FilterContext.class);
            org.mockito.Mockito.when(ctx.next(reqSpec, respSpec)).thenAnswer(inv -> {
                var params = reqSpec.getConfig().getHttpClientConfig().params();
                assertThat(params.get("http.connection.timeout")).isEqualTo(12_345);
                assertThat(params.get("http.socket.timeout")).isEqualTo(54_321);
                assertThat(params.get("http.connection-manager.timeout")).isEqualTo(23_456L);
                return org.mockito.Mockito.mock(Response.class);
            });
            try (var s = PinnedTargetHttpSupport.pin(t1)) {
                filter.filter(reqSpec, respSpec, ctx);
            }
        } finally {
            restoreSysProp("scim.http.connectTimeoutMs", prevConnect);
            restoreSysProp("scim.http.socketTimeoutMs", prevSocket);
            restoreSysProp("scim.http.connectionManagerTimeoutMs", prevConnMgr);
        }

        assertThat(PinnedTargetHttpSupport.resolvePositiveIntConfig("not-a-number", "-5", 10_000)).isEqualTo(10_000);
        assertThat(PinnedTargetHttpSupport.resolvePositiveIntConfig(null, "999999999999", 10_000)).isEqualTo(10_000);
        assertThat(PinnedTargetHttpSupport.resolvePositiveIntConfig("  ", "7500", 10_000)).isEqualTo(7_500);
    }

    @Test
    void concurrentPinAndCloseChurnOnSameHostnameNeverDropsActiveRegistration() throws Exception {
        TargetUrlPolicy.ResolvedTarget target = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://churn.example.test/scim/v2"),
                "churn.example.test",
                List.of(InetAddress.getByName("93.184.216.34")));

        int threads = 8;
        int iterationsPerThread = 500;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        java.util.concurrent.CyclicBarrier startBarrier = new java.util.concurrent.CyclicBarrier(threads);
        java.util.concurrent.atomic.AtomicBoolean missingWhilePinned = new java.util.concurrent.atomic.AtomicBoolean(false);

        try {
            List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>(threads);
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    startBarrier.await(5, TimeUnit.SECONDS);
                    for (int i = 0; i < iterationsPerThread; i++) {
                        try (var ignored = PinnedTargetHttpSupport.pin(target)) {
                            if (!PinnedTargetHttpSupport.hasActivePinForHost("churn.example.test")) {
                                missingWhilePinned.set(true);
                            }
                        }
                    }
                    return null;
                }));
            }
            for (java.util.concurrent.Future<?> future : futures) {
                future.get(15, TimeUnit.SECONDS);
            }
            assertThat(missingWhilePinned.get()).isFalse();
            assertThat(PinnedTargetHttpSupport.hasActivePinForHost("churn.example.test")).isFalse();
        } finally {
            pool.shutdownNow();
        }
    }

    private static void restoreSysProp(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}
