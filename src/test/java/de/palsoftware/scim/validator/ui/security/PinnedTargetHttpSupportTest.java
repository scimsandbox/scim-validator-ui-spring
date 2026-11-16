package de.palsoftware.scim.validator.ui.security;

import com.sun.net.httpserver.HttpServer;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RedirectConfig;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.filter.OrderedFilter;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;
import org.apache.http.HttpHost;
import org.apache.http.HttpVersion;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.HttpInetSocketAddress;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opentest4j.TestAbortedException;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PinnedTargetHttpSupportTest {

    private static HttpServer server;
    private static int port;
    private static final AtomicReference<String> lastHostHeader = new AtomicReference<>();
    private static final AtomicReference<String> lastMethod = new AtomicReference<>();
    private static final AtomicReference<String> lastBody = new AtomicReference<>();

    @BeforeAll
    static void startServer() throws IOException {
        PinnedTargetHttpSupport.initializeJvmDnsPinning();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();

        server.createContext("/test", exchange -> {
            lastHostHeader.set(exchange.getRequestHeaders().getFirst("Host"));
            lastMethod.set(exchange.getRequestMethod());
            try (InputStream is = exchange.getRequestBody()) {
                lastBody.set(new String(is.readAllBytes(), StandardCharsets.UTF_8));
            }
            byte[] body = "{\"status\":\"pinned-ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/scim+json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/redirect-same-302", exchange -> {
            drainRequestBody(exchange.getRequestBody());
            exchange.getResponseHeaders().set("Location", "/test");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        server.createContext("/redirect-same-307", exchange -> {
            drainRequestBody(exchange.getRequestBody());
            exchange.getResponseHeaders().set("Location", "/test");
            exchange.sendResponseHeaders(307, -1);
            exchange.close();
        });

        server.createContext("/redirect-same-308", exchange -> {
            drainRequestBody(exchange.getRequestBody());
            exchange.getResponseHeaders().set("Location", "/test");
            exchange.sendResponseHeaders(308, -1);
            exchange.close();
        });

        server.createContext("/redirect-cross-origin", exchange -> {
            drainRequestBody(exchange.getRequestBody());
            exchange.getResponseHeaders().set("Location", "http://169.254.169.254/latest/meta-data/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        server.start();
    }

    private static void drainRequestBody(InputStream is) throws IOException {
        try (InputStream in = is) {
            in.readAllBytes();
        }
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void restAssuredPinningUsesPublicSocketFactoriesFollowsSafeRedirectsBlocksUnsafeRedirectsAndTracksConnections()
            throws Exception {
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

        // Distinct hostname for unpinned negative check so standard JVM negative DNS cache does not affect pinned test
        assertThatThrownBy(() -> RestAssured.given()
                .baseUri("http://unpinned-restassured.example.test:" + port)
                .get("/test"))
                .isInstanceOf(UnknownHostException.class);

        String baseUri = "http://pinned-restassured.example.test:" + port;
        TargetUrlPolicy.ResolvedTarget pinnedTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create(baseUri),
                "pinned-restassured.example.test",
                List.of(InetAddress.getByName("127.0.0.1")));

        PinnedTargetHttpSupport.PinnedScopeImpl capturedScope;
        try (var scope = PinnedTargetHttpSupport.pin(pinnedTarget)) {
            capturedScope = (PinnedTargetHttpSupport.PinnedScopeImpl) scope;
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(pinnedTarget);

            // 1. Direct request connects via PinnedPlainSocketFactory while preserving Host header
            Response okResponse = RestAssured.given().baseUri(baseUri).get("/test");
            assertThat(okResponse.statusCode()).isEqualTo(200);
            assertThat(okResponse.body().asString()).contains("pinned-ok");
            assertThat(lastHostHeader.get()).isEqualTo("pinned-restassured.example.test:" + port);

            // 2. Safe same-origin 302 redirect IS followed when redirects are enabled
            Response followed302 = RestAssured.given().baseUri(baseUri).get("/redirect-same-302");
            assertThat(followed302.statusCode()).isEqualTo(200);
            assertThat(followed302.body().asString()).contains("pinned-ok");

            // 3. Safe same-origin 307 and 308 method-preserving POST redirects ARE followed with body preserved
            for (String path : List.of("/redirect-same-307", "/redirect-same-308")) {
                Response followedPost = RestAssured.given()
                        .baseUri(baseUri)
                        .contentType("application/scim+json")
                        .body("{\"userName\":\"alice\"}")
                        .post(path);
                assertThat(followedPost.statusCode()).isEqualTo(200);
                assertThat(lastMethod.get()).isEqualTo("POST");
                assertThat(lastBody.get()).isEqualTo("{\"userName\":\"alice\"}");
            }

            // 4. Explicit .redirects().follow(false) (as in Rfc7644MeSpec.meGet) keeps 308 visible unfollowed
            Response unfollowed308 = RestAssured.given()
                    .baseUri(baseUri)
                    .redirects().follow(false)
                    .get("/redirect-same-308");
            assertThat(unfollowed308.statusCode()).isEqualTo(308);
            assertThat(unfollowed308.getHeader("Location")).isEqualTo("/test");

            // 5. Cross-origin redirect is NOT followed even when caller enables redirects
            Response blockedCrossRedirect = RestAssured.given()
                    .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(true)))
                    .baseUri(baseUri)
                    .get("/redirect-cross-origin");
            assertThat(blockedCrossRedirect.statusCode()).isEqualTo(302);
            assertThat(blockedCrossRedirect.getHeader("Location"))
                    .isEqualTo("http://169.254.169.254/latest/meta-data/");

            // 6. Untrusted valid origin on a follow-up request aborts test via TestAbortedException before connecting
            assertThatThrownBy(() -> RestAssured.given()
                    .baseUri("http://other-origin.example.test:" + port)
                    .get("/test"))
                    .isInstanceOf(TestAbortedException.class)
                    .hasMessageContaining("does not match configured SCIM origin");

            // 7. Reject .auth().certificate(...) (CertAuthScheme), .relaxedHTTPSValidation() (SSLConfig), and .proxy(...)
            assertThatThrownBy(() -> RestAssured.given()
                    .auth().certificate("keystore.jks", "secret")
                    .baseUri(baseUri)
                    .get("/test"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Certificate authentication scheme");

            assertThatThrownBy(() -> RestAssured.given()
                    .relaxedHTTPSValidation()
                    .baseUri(baseUri)
                    .get("/test"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Custom or relaxed SSL configuration");

            assertThatThrownBy(() -> RestAssured.given()
                    .proxy("127.0.0.1", 8888)
                    .baseUri(baseUri)
                    .get("/test"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Outbound proxy specification");

            assertThat(capturedScope.trackedConnectionManagerCount()).isGreaterThan(0);

            // Nested pin scope restores outer scope when closed
            TargetUrlPolicy.ResolvedTarget nestedTarget = new TargetUrlPolicy.ResolvedTarget(
                    URI.create("https://nested-restassured.example.test:8443"),
                    "nested-restassured.example.test",
                    List.of(InetAddress.getByName("93.184.216.34")));
            try (var nested = PinnedTargetHttpSupport.pin(nestedTarget)) {
                assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(nestedTarget);
            }
            assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isEqualTo(pinnedTarget);
        }

        // Scope close shuts down all tracked ClientConnectionManagers, is idempotent, and rejects late additions
        assertThat(capturedScope.trackedConnectionManagerCount()).isZero();
        capturedScope.close();
        assertThat(PinnedTargetHttpSupport.currentPinnedTarget()).isNull();

        ClientConnectionManager lateManager = Mockito.mock(ClientConnectionManager.class);
        assertThatThrownBy(() -> capturedScope.trackConnectionManager(lateManager))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already closed");
        Mockito.verify(lateManager).shutdown();
    }

    @Test
    void jdkHttpClientUsesPinnedInetAddressResolverAcrossAsyncWorkerThreadsAndReferenceCountsOverlappingPins()
            throws Exception {
        assertThat(PinnedTargetHttpSupport.currentBuiltinResolver()).isNotNull();

        ExecutorService preStartedPool = Executors.newSingleThreadExecutor();
        preStartedPool.submit(() -> null).get(5, TimeUnit.SECONDS);

        HttpClient jdkClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();

        try {
            // 1. Unpinned hostname fails resolution
            HttpRequest unpinnedReq = HttpRequest.newBuilder(
                            URI.create("http://unpinned-jdk.example.test:" + port + "/test"))
                    .GET()
                    .build();
            assertThatThrownBy(() -> jdkClient.send(unpinnedReq, HttpResponse.BodyHandlers.ofString()))
                    .isInstanceOf(IOException.class);

            // 2. Pinned hostname resolves across main thread and pre-started worker threads with reference counting
            TargetUrlPolicy.ResolvedTarget pinnedTarget = new TargetUrlPolicy.ResolvedTarget(
                    URI.create("http://pinned-async.example.test:" + port),
                    "pinned-async.example.test",
                    List.of(InetAddress.getByName("127.0.0.1")));
            HttpRequest pinnedReq = HttpRequest.newBuilder(
                            URI.create("http://pinned-async.example.test:" + port + "/test"))
                    .GET()
                    .build();

            var scope1 = PinnedTargetHttpSupport.pin(pinnedTarget);
            var scope2 = PinnedTargetHttpSupport.pin(pinnedTarget);
            try {
                HttpResponse<String> resp1 = jdkClient.send(pinnedReq, HttpResponse.BodyHandlers.ofString());
                assertThat(resp1.statusCode()).isEqualTo(200);
                assertThat(resp1.body()).contains("pinned-ok");
                assertThat(lastHostHeader.get()).startsWith("pinned-async.example.test");

                HttpResponse<String> asyncResp = preStartedPool.submit(
                                () -> jdkClient.send(pinnedReq, HttpResponse.BodyHandlers.ofString()))
                        .get(5, TimeUnit.SECONDS);
                assertThat(asyncResp.statusCode()).isEqualTo(200);
                assertThat(asyncResp.body()).contains("pinned-ok");

                // resolveUnpinned bypasses both ACTIVE_PINS and InetAddress.cache
                assertThatThrownBy(() -> PinnedTargetHttpSupport.resolveUnpinned("pinned-async.example.test"))
                        .isInstanceOf(UnknownHostException.class);
                assertThat(PinnedTargetHttpSupport.resolveUnpinned("localhost")).isNotEmpty();

                // Closing scope1 leaves scope2's registration active
                scope1.close();
                assertThat(PinnedTargetHttpSupport.hasActivePinForHost("pinned-async.example.test")).isTrue();
                HttpResponse<String> stillPinnedResp = preStartedPool.submit(
                                () -> jdkClient.send(pinnedReq, HttpResponse.BodyHandlers.ofString()))
                        .get(5, TimeUnit.SECONDS);
                assertThat(stillPinnedResp.statusCode()).isEqualTo(200);
            } finally {
                scope2.close();
                scope1.close();
            }
            assertThat(PinnedTargetHttpSupport.hasActivePinForHost("pinned-async.example.test")).isFalse();

            // 3. Eviction check on fresh hostname (never positively cached) fails once pin scope closes
            TargetUrlPolicy.ResolvedTarget evictedTarget = new TargetUrlPolicy.ResolvedTarget(
                    URI.create("http://closed-pin.example.test:" + port),
                    "closed-pin.example.test",
                    List.of(InetAddress.getByName("127.0.0.1")));
            try (var tempScope = PinnedTargetHttpSupport.pin(evictedTarget)) {
                assertThat(PinnedTargetHttpSupport.hasActivePinForHost("closed-pin.example.test")).isTrue();
            }
            assertThat(PinnedTargetHttpSupport.hasActivePinForHost("closed-pin.example.test")).isFalse();
            HttpRequest evictedReq = HttpRequest.newBuilder(
                            URI.create("http://closed-pin.example.test:" + port + "/test"))
                    .GET()
                    .build();
            assertThatThrownBy(() -> jdkClient.send(evictedReq, HttpResponse.BodyHandlers.ofString()))
                    .isInstanceOf(IOException.class);
        } finally {
            preStartedPool.shutdownNow();
        }
    }

    @Test
    void validateValidatorRequestUriAndSafePinnedRedirectStrategyEnforceOriginUpgradeDowngradeAndSyntaxRules()
            throws Exception {
        TargetUrlPolicy.ResolvedTarget httpTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("http://scim.example.com:8080/scim/v2"),
                "scim.example.com",
                List.of(InetAddress.getByName("93.184.216.34")));
        TargetUrlPolicy.ResolvedTarget httpsTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com/scim/v2"),
                "scim.example.com",
                List.of(InetAddress.getByName("93.184.216.34")));

        // Same-origin and http -> https:443 upgrade are allowed
        assertThat(PinnedTargetHttpSupport.validateValidatorRequestUri(
                httpTarget, "http://SCIM.EXAMPLE.COM.:8080/scim/v2/Users")).isNotNull();
        assertThat(PinnedTargetHttpSupport.validateValidatorRequestUri(
                httpTarget, "https://scim.example.com/scim/v2/Users")).isNotNull();
        assertThat(PinnedTargetHttpSupport.validateValidatorRequestUri(
                httpTarget, "https://scim.example.com:443/scim/v2/Users")).isNotNull();
        assertThat(PinnedTargetHttpSupport.validateValidatorRequestUri(
                httpsTarget, "https://scim.example.com:443/scim/v2/Me")).isNotNull();

        // Untrusted valid http/https origins & https -> http downgrade throw TestAbortedException (ABORTED, not FAILED)
        for (String untrusted : List.of(
                "http://scim.example.com/scim/v2/Users/me",
                "https://scim.example.com:8443/scim/v2/Users",
                "https://attacker.example.org/scim/v2/Users")) {
            assertThatThrownBy(() -> PinnedTargetHttpSupport.validateValidatorRequestUri(httpsTarget, untrusted))
                    .isInstanceOf(TestAbortedException.class);
        }
        assertThatThrownBy(() -> PinnedTargetHttpSupport.validateValidatorRequestUri(
                httpTarget, "https://scim.example.com:8443/scim/v2/Users"))
                .isInstanceOf(TestAbortedException.class);

        // Malformed, unsafe, non-HTTP(S), userinfo, zone-id, invalid port, or root-escaping URLs throw IllegalArgumentException
        for (String invalid : List.of(
                "",
                "   ",
                "https://scim.example.com/Users\u0007",
                "https://scim.example.com\\evil",
                "//evil.example.org/Users",
                "https://exa mple.com/Users",
                "ftp://scim.example.com/Users",
                "https://user:secret@scim.example.com/Users",
                "https:///Users",
                "https://./Users",
                "https://[fe80::1%25eth0]/Users",
                "https://scim.example.com:0/Users",
                "https://scim.example.com:70000/Users",
                "https://scim.example.com/..",
                "https://scim.example.com/../etc/passwd")) {
            assertThatThrownBy(() -> PinnedTargetHttpSupport.validateValidatorRequestUri(httpsTarget, invalid))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> PinnedTargetHttpSupport.validateValidatorRequestUri(httpsTarget, null))
                .isInstanceOf(IllegalArgumentException.class);

        // Direct SafePinnedRedirectStrategy branch coverage (upgrade, downgrade, unsafe Location, context edge cases)
        var httpStrategy = new PinnedTargetHttpSupport.SafePinnedRedirectStrategy(httpTarget);
        var httpsStrategy = new PinnedTargetHttpSupport.SafePinnedRedirectStrategy(httpsTarget);

        assertThat(httpStrategy.isRedirected(null, null, null)).isFalse();

        BasicHttpContext httpCtx = new BasicHttpContext();
        httpCtx.setAttribute(HttpCoreContext.HTTP_TARGET_HOST, new HttpHost("scim.example.com", 8080, "http"));
        BasicHttpRequest getReq = new BasicHttpRequest("GET", "/scim/v2/Me");

        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https://scim.example.com/scim/v2/Users/1"), httpCtx))
                .isTrue();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https://scim.example.com:8443/scim/v2/Users/1"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(200, "/scim/v2/Users/1"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, null), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "   "), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "//evil.example.org/x"), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "http://scim.example.com:8080/bad\\path"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https://user:pw@scim.example.com/x"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "ftp://scim.example.com/x"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https:///x"), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https://[::1%25eth0]/x"), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "https://scim.example.com:70000/x"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "http://scim.example.com:8080/../escape"), httpCtx))
                .isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "http://[not-uri"), httpCtx)).isFalse();
        assertThat(httpStrategy.isRedirected(getReq, redirectResponse(302, "/scim/v2/Users/1"), new BasicHttpContext()))
                .isFalse();
        BasicHttpRequest absReq = new BasicHttpRequest("GET", "http://scim.example.com:8080/scim/v2/Me");
        assertThat(httpStrategy.isRedirected(absReq, redirectResponse(302, "/scim/v2/Users/1"), httpCtx)).isTrue();

        BasicHttpContext httpsCtx = new BasicHttpContext();
        httpsCtx.setAttribute(HttpCoreContext.HTTP_TARGET_HOST, new HttpHost("scim.example.com", 443, "https"));
        assertThat(httpsStrategy.isRedirected(getReq, redirectResponse(302, "http://scim.example.com/scim/v2/Users/1"), httpsCtx))
                .isFalse();

        // Loopback managementPort == 443 blocks http -> https:443 upgrade in both validateValidatorRequestUri and SafePinnedRedirectStrategy
        TargetUrlPolicy.ResolvedTarget loopbackMgmt443 = new TargetUrlPolicy.ResolvedTarget(
                URI.create("http://127.0.0.1:8080/scim/v2"),
                "127.0.0.1",
                List.of(InetAddress.getByName("127.0.0.1")),
                443);
        assertThat(loopbackMgmt443.isBlockedLoopbackManagementPort(443)).isTrue();
        assertThat(loopbackMgmt443.isBlockedLoopbackManagementPort(8080)).isFalse();
        assertThat(new TargetUrlPolicy.ResolvedTarget(
                URI.create("http://127.0.0.1:8080/scim/v2"),
                "127.0.0.1",
                List.of(InetAddress.getByName("127.0.0.1")),
                0).isBlockedLoopbackManagementPort(443)).isFalse();
        assertThat(new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com/scim/v2"),
                "scim.example.com",
                List.of(InetAddress.getByName("93.184.216.34")),
                443).isBlockedLoopbackManagementPort(443)).isFalse();

        assertThatThrownBy(() -> PinnedTargetHttpSupport.validateValidatorRequestUri(
                loopbackMgmt443, "https://127.0.0.1/scim/v2/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("management port 443");

        var loopbackMgmt443Strategy = new PinnedTargetHttpSupport.SafePinnedRedirectStrategy(loopbackMgmt443);
        BasicHttpContext loopbackHttpCtx = new BasicHttpContext();
        loopbackHttpCtx.setAttribute(HttpCoreContext.HTTP_TARGET_HOST, new HttpHost("127.0.0.1", 8080, "http"));
        assertThat(loopbackMgmt443Strategy.isRedirected(
                getReq, redirectResponse(302, "https://127.0.0.1/scim/v2/Users"), loopbackHttpCtx))
                .isFalse();

        URI emptyPathWithQuery = URI.create("https://scim.example.com?filter=a#frag");
        assertThat(PinnedTargetHttpSupport.ensureNonEmptyPath(emptyPathWithQuery).toString())
                .isEqualTo("https://scim.example.com/?filter=a#frag");
        assertThat(PinnedTargetHttpSupport.ensureNonEmptyPath(URI.create("https://scim.example.com")).toString())
                .isEqualTo("https://scim.example.com/");
        assertThat(PinnedTargetHttpSupport.ensureNonEmptyPath(null)).isNull();
    }

    private static org.apache.http.HttpResponse redirectResponse(int status, String location) {
        org.apache.http.HttpResponse resp = DefaultHttpResponseFactory.INSTANCE.newHttpResponse(
                new BasicStatusLine(HttpVersion.HTTP_1_1, status, "Redirect"), null);
        if (location != null) {
            resp.setHeader("Location", location);
        }
        return resp;
    }

    @Test
    void pinnedSocketFactoriesLookupPolicyNormalizationAndFilterEdgeBranchesWork() throws Exception {
        InetAddress v4 = InetAddress.getByName("93.184.216.34");
        InetAddress v4Secondary = InetAddress.getByName("93.184.216.35");
        InetAddress v6 = InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946");

        // 1. Pinned socket factories & resolvePinnedConnectAddress defense-in-depth checks
        TargetUrlPolicy.ResolvedTarget dualIpTarget = new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com/scim/v2"),
                "scim.example.com",
                List.of(v4, v4Secondary));
        DnsResolver pinnedResolver = PinnedTargetHttpSupport.dnsResolverFor(dualIpTarget);

        HttpInetSocketAddress matchedSecondIp = PinnedTargetHttpSupport.resolvePinnedConnectAddress(
                pinnedResolver,
                new HttpInetSocketAddress(new HttpHost("scim.example.com", 443, "https"), v4Secondary, 443),
                "https");
        assertThat(matchedSecondIp.getAddress()).isEqualTo(v4Secondary);

        // Stale/rebound address in InetSocketAddress is overridden with allowed[0]
        InetAddress reboundPrivate = InetAddress.getByName("169.254.169.254");
        HttpInetSocketAddress overriddenStale = PinnedTargetHttpSupport.resolvePinnedConnectAddress(
                pinnedResolver,
                new HttpInetSocketAddress(new HttpHost("scim.example.com", 443, "https"), reboundPrivate, 443),
                "https");
        assertThat(overriddenStale.getAddress()).isEqualTo(v4);

        HttpInetSocketAddress plainAddrPinned = PinnedTargetHttpSupport.resolvePinnedConnectAddress(
                pinnedResolver,
                InetSocketAddress.createUnresolved("scim.example.com", 80),
                "http");
        assertThat(plainAddrPinned.getAddress()).isEqualTo(v4);

        assertThatThrownBy(() -> PinnedTargetHttpSupport.resolvePinnedConnectAddress(
                host -> new InetAddress[0],
                InetSocketAddress.createUnresolved("scim.example.com", 443),
                "https"))
                .isInstanceOf(UnknownHostException.class);

        var httpsFactory = new PinnedTargetHttpSupport.PinnedStrictHttpsSocketFactory(pinnedResolver);
        assertThat(httpsFactory.getHostnameVerifier()).isSameAs(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
        try (SSLSocket sslSocket = (SSLSocket) javax.net.ssl.SSLSocketFactory.getDefault().createSocket()) {
            httpsFactory.prepareSocket(sslSocket);
            assertThat(sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm()).isEqualTo("HTTPS");
        }
        assertThatThrownBy(() -> httpsFactory.connectSocket(
                null,
                InetSocketAddress.createUnresolved("attacker.example.com", 443),
                null,
                null))
                .isInstanceOf(UnknownHostException.class);

        // 2. LookupPolicy filtering & ordering
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(List.of(v4, v6), null).toList())
                .containsExactly(v4, v6);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                        List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV4)).toList())
                .containsExactly(v4);
        assertThat(PinnedTargetHttpSupport.PinnedInetAddressResolver.applyLookupPolicy(
                        List.of(v4, v6), LookupPolicy.of(LookupPolicy.IPV6)).toList())
                .containsExactly(v6);
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

            InetAddressResolver mockBuiltin = Mockito.mock(InetAddressResolver.class);
            Mockito.when(mockBuiltin.lookupByAddress(v4.getAddress())).thenReturn("example.com");
            Mockito.when(mockBuiltin.lookupByName(Mockito.eq("empty.example.test"), Mockito.any()))
                    .thenAnswer(inv -> Stream.empty());

            PinnedTargetHttpSupport.installBuiltinResolver(mockBuiltin);
            var resolver = new PinnedTargetHttpSupport.PinnedInetAddressResolver(mockBuiltin);
            assertThat(resolver.lookupByAddress(v4.getAddress())).isEqualTo("example.com");
            assertThat(resolver.lookupByName("empty.example.test", LookupPolicy.of(LookupPolicy.IPV4)).toList()).isEmpty();
            assertThatThrownBy(() -> PinnedTargetHttpSupport.resolveUnpinned("empty.example.test"))
                    .isInstanceOf(UnknownHostException.class);

            PinnedInetAddressResolverProvider.BUILTIN_RESOLVER.set(null);
            assertThat(PinnedTargetHttpSupport.resolveUnpinned("localhost")).isNotEmpty();
        } finally {
            if (existingBuiltin != null) {
                PinnedTargetHttpSupport.installBuiltinResolver(existingBuiltin);
            }
        }

        // 3. Host normalization & PinnedDnsResolver checks
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
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("93.184.216.34")).isEqualTo("93.184.216.34");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("999.999.999.999")).isEqualTo("999.999.999.999");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[fe80::1%eth0]")).isEqualTo("fe80::1%eth0");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("/not-a-host")).isEqualTo("/not-a-host");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("1invalid.example.com")).isEqualTo("1invalid.example.com");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("bücher.example.com."))
                .isEqualTo("xn--bcher-kva.example.com");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[]")).isEqualTo("[]");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("[unclosed")).isEqualTo("[unclosed");
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost(null)).isEmpty();
        assertThat(PinnedTargetHttpSupport.normalizeDnsHost("   ")).isEmpty();
        assertThatThrownBy(() -> pinnedResolver.resolve("attacker.example.com"))
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("Blocked outbound connection to unpinned host");
        assertThatThrownBy(() -> pinnedResolver.resolve(null)).isInstanceOf(UnknownHostException.class);
        assertThatThrownBy(() -> pinnedResolver.resolve("   ")).isInstanceOf(UnknownHostException.class);

        // 4. Filter edge branches (unsupported HttpClient, clientReused=true, capRedirectConfig)
        var filter = new PinnedTargetHttpSupport.PinnedRestAssuredFilter();
        assertThat(filter.getOrder()).isEqualTo(OrderedFilter.HIGHEST_PRECEDENCE);
        assertThat(PinnedTargetHttpSupport.PinnedRestAssuredFilter.capRedirectConfig(null).maxRedirects()).isEqualTo(5);
        assertThat(PinnedTargetHttpSupport.PinnedRestAssuredFilter.capRedirectConfig(
                RedirectConfig.redirectConfig().maxRedirects(3)).maxRedirects()).isEqualTo(3);

        FilterableRequestSpecification unsupportedSpec = Mockito.mock(FilterableRequestSpecification.class);
        FilterableResponseSpecification respSpec = Mockito.mock(FilterableResponseSpecification.class);
        FilterContext filterCtx = Mockito.mock(FilterContext.class);
        Mockito.when(filterCtx.next(unsupportedSpec, respSpec)).thenReturn(Mockito.mock(Response.class));
        assertThat(filter.filter(unsupportedSpec, respSpec, filterCtx)).isNotNull();

        Mockito.when(unsupportedSpec.getURI()).thenReturn("https://scim.example.com/scim/v2/Users");
        Mockito.when(unsupportedSpec.getHttpClient()).thenReturn(null);
        try (var scope = PinnedTargetHttpSupport.pin(dualIpTarget)) {
            assertThatThrownBy(() -> filter.filter(unsupportedSpec, respSpec, filterCtx))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("null");

            org.apache.http.client.HttpClient customNonAbstract = Mockito.mock(org.apache.http.client.HttpClient.class);
            Mockito.when(unsupportedSpec.getHttpClient()).thenReturn(customNonAbstract);
            assertThatThrownBy(() -> filter.filter(unsupportedSpec, respSpec, filterCtx))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Unsupported RestAssured HttpClient");
        }
    }

    @Test
    void outOfOrderScopeCloseNonInheritableThreadLocalAndTimeoutConfigurationWork() throws Exception {
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

        var scope1 = PinnedTargetHttpSupport.pin(t1);
        var scope2 = PinnedTargetHttpSupport.pin(t2);
        try {
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

        // Default and overridden ScimBaseSpec-aligned timeouts + reused HttpClient branch
        assertThat(PinnedTargetHttpSupport.resolveConnectTimeoutMs()).isEqualTo(10_000);
        assertThat(PinnedTargetHttpSupport.resolveSocketTimeoutMs()).isEqualTo(60_000);
        assertThat(PinnedTargetHttpSupport.resolveConnectionManagerTimeoutMs()).isEqualTo(10_000L);

        String prevConnect = System.getProperty("scim.http.connectTimeoutMs");
        String prevSocket = System.getProperty("scim.http.socketTimeoutMs");
        String prevConnMgr = System.getProperty("scim.http.connectionManagerTimeoutMs");
        try {
            System.setProperty("scim.http.connectTimeoutMs", "12345");
            System.setProperty("scim.http.socketTimeoutMs", "54321");
            System.setProperty("scim.http.connectionManagerTimeoutMs", "23456");

            TargetUrlPolicy.ResolvedTarget reusedTarget = new TargetUrlPolicy.ResolvedTarget(
                    URI.create("http://reused-client.example.test:" + port),
                    "reused-client.example.test",
                    List.of(InetAddress.getByName("127.0.0.1")));
            @SuppressWarnings("deprecation")
            org.apache.http.impl.client.DefaultHttpClient callerClient =
                    new org.apache.http.impl.client.DefaultHttpClient();
            try (var s = PinnedTargetHttpSupport.pin(reusedTarget)) {
                PinnedTargetHttpSupport.PinnedScopeImpl scopeImpl = (PinnedTargetHttpSupport.PinnedScopeImpl) s;
                Response reusedResp = RestAssured.given()
                        .config(RestAssured.config().httpClient(HttpClientConfig.httpClientConfig()
                                .reuseHttpClientInstance()
                                .httpClientFactory(() -> callerClient)))
                        .baseUri("http://reused-client.example.test:" + port)
                        .get("/test");
                assertThat(reusedResp.statusCode()).isEqualTo(200);
                // clientReused == true does not track caller-owned connection manager for scope shutdown
                assertThat(scopeImpl.trackedConnectionManagerCount()).isZero();

                HttpParams clientParams = callerClient.getParams();
                assertThat(HttpConnectionParams.getConnectionTimeout(clientParams)).isEqualTo(12_345);
                assertThat(HttpConnectionParams.getSoTimeout(clientParams)).isEqualTo(54_321);
                assertThat(HttpClientParams.getConnectionManagerTimeout(clientParams)).isEqualTo(23_456L);
                assertThat(HttpClientParams.getCookiePolicy(clientParams)).isEqualTo(CookiePolicy.IGNORE_COOKIES);
            } finally {
                callerClient.getConnectionManager().shutdown();
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
        CyclicBarrier startBarrier = new CyclicBarrier(threads);
        AtomicBoolean missingWhilePinned = new AtomicBoolean(false);

        try {
            List<Future<?>> futures = new ArrayList<>(threads);
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
            for (Future<?> future : futures) {
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
