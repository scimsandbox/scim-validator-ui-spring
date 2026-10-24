package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import de.palsoftware.scim.validator.ui.mock.MockGitHubApiServer;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceCatalogEntry;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Empirical Challenger Verification Suite for GitHub Compliance Publisher & Mock GitHub API Server.
 * Stress-tests concurrency, fault injection (405, 422, 404, 401), branch cleanup invariant in finally,
 * and corrupt/adversarial PEM private key handling.
 */
class GitHubCompliancePublisherChallengerTest {

    private MockGitHubApiServer mockServer;
    private KeyPair rsaKeyPair;
    private String pkcs8Pem;
    private ObjectMapper objectMapper;
    private ComplianceBadgeGenerator badgeGenerator;
    private ComplianceReportGenerator reportGenerator;
    private GitHubAuthService authService;
    private GitHubCompliancePublisherService publisherService;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        byte[] pkcs8Bytes = rsaKeyPair.getPrivate().getEncoded();
        pkcs8Pem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs8Bytes) +
                "\n-----END PRIVATE KEY-----";

        mockServer = new MockGitHubApiServer();
        objectMapper = new ObjectMapper();
        badgeGenerator = new ComplianceBadgeGenerator();
        reportGenerator = new ComplianceReportGenerator();

        authService = new GitHubAuthService(
                "123456",
                "78910",
                pkcs8Pem,
                mockServer.getBaseUrl(),
                objectMapper,
                HttpClient.newHttpClient()
        );

        publisherService = new GitHubCompliancePublisherService(
                authService,
                reportGenerator,
                badgeGenerator,
                objectMapper,
                HttpClient.newHttpClient(),
                mockServer.getBaseUrl()
        );
        publisherService.setEnabled(true);
        publisherService.setRepo("scimsandbox/scim-website");
        publisherService.setBranch("main");
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.close();
        }
    }

    // =========================================================================
    // 1. CONCURRENCY & LOCK SERIALIZATION STRESS TESTS
    // =========================================================================

    @Test
    @DisplayName("Stress Test: 10 concurrent publish executions under fair ReentrantLock serialize cleanly without branch collisions")
    void testConcurrentPublishUnderHighContention() throws Exception {
        int concurrency = 10;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(concurrency);

        List<CompliancePublicationResult> results = new CopyOnWriteArrayList<>();
        List<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int i = 0; i < concurrency; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    startLatch.await(); // Synchronize all threads at the gate
                    UUID runId = UUID.randomUUID();
                    CompliancePublishRequest req = new CompliancePublishRequest(
                            runId,
                            "ConcurrentProduct " + index,
                            "concurrent-product-" + index,
                            "1.0." + index,
                            "Vendor " + index,
                            "https://example.com/p" + index,
                            "Apache-2.0",
                            80 + index,
                            "EMERALD",
                            8,
                            10
                    );
                    CompliancePublicationResult res = publisherService.publish(req);
                    results.add(res);
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // Unleash all threads simultaneously
        boolean finished = doneLatch.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(finished).as("All concurrent publishing tasks should complete within timeout").isTrue();
        assertThat(errors).as("No threads should encounter exceptions under fair lock").isEmpty();
        assertThat(results).hasSize(concurrency);

        for (CompliancePublicationResult result : results) {
            assertThat(result.success()).isTrue();
            assertThat(result.prUrl()).isNotBlank();
            assertThat(result.mergeCommitSha()).isNotBlank();
        }

        // Verify Branch Lifecycle: Exactly concurrency branches created, and all deleted in finally
        List<MockGitHubApiServer.RecordedRequest> recorded = mockServer.getRecordedRequests();
        long branchCreations = recorded.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .count();
        long branchDeletions = recorded.stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains("/git/refs/heads/publish/"))
                .count();

        assertThat(branchCreations).as("Every concurrent publish should create its branch").isEqualTo(concurrency);
        assertThat(branchDeletions).as("Every created branch must be deleted in finally").isEqualTo(concurrency);
    }

    @Test
    @DisplayName("Stress Test: Double-checked locking prevents duplicate token exchanges under 20 concurrent threads")
    void testConcurrentAuthTokenExchangeDoubleCheckedLocking() throws Exception {
        int threads = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        List<String> tokens = new CopyOnWriteArrayList<>();
        List<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    String token = authService.getInstallationAccessToken();
                    tokens.add(token);
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(completed).isTrue();
        assertThat(errors).isEmpty();
        assertThat(tokens).hasSize(threads);

        // All 20 threads must receive the EXACT SAME token instance
        String firstToken = tokens.get(0);
        for (String t : tokens) {
            assertThat(t).isEqualTo(firstToken);
        }

        // Double-checked locking verification: exactly 1 HTTP request made to /app/installations/:id/access_tokens
        long tokenExchangeRequests = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().contains("/access_tokens"))
                .count();
        assertThat(tokenExchangeRequests).as("Exactly 1 token exchange request should be made despite 20 concurrent callers").isEqualTo(1);
    }

    // =========================================================================
    // 2. FAULT INJECTION TESTS: 405, 422, 404, 401
    // =========================================================================

    @Test
    @DisplayName("Fault Injection (422): Recovers from 'Reference already exists' by deleting stale branch and recreating")
    void testBranchAlreadyExists422Recovery() {
        mockServer.setSimulateBranchExists(true);

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "422 Product", "p422", "1.0.0",
                "Vendor", "https://example.com", "MIT", 90, "EMERALD", 9, 10
        );

        CompliancePublicationResult result = publisherService.publish(request);
        assertThat(result.success()).isTrue();

        List<MockGitHubApiServer.RecordedRequest> requests = mockServer.getRecordedRequests();
        String shortId = runId.toString().substring(0, 8);
        String targetBranch = "publish/p422-" + shortId;

        // Verify recovery sequence:
        // 1. POST /git/refs (returns 422)
        // 2. DELETE /git/refs/heads/publish/p422-... (clearing stale branch)
        // 3. POST /git/refs (retry succeeds with 201)
        // ... flow continues ...
        // 4. DELETE /git/refs/heads/publish/p422-... (step 10 cleanup in finally)
        long postRefCalls = requests.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .count();
        assertThat(postRefCalls).as("Branch creation should have been attempted twice (1 initial + 1 retry)").isEqualTo(2);

        long deleteRefCalls = requests.stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains(targetBranch))
                .count();
        assertThat(deleteRefCalls).as("Branch should have been deleted twice: once on 422 recovery, once in finally").isEqualTo(2);
    }

    @Test
    @DisplayName("Fault Injection (405): Retries on merge conflict with backoff jitter and succeeds on attempt 2")
    void testMergeConflict405RetrySuccess() {
        mockServer.setSimulateMergeConflictTimes(1);

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Conflict Product", "conflict-p", "1.0.0",
                "Vendor", "https://example.com", "MIT", 85, "TEAL_GREEN", 8, 10
        );

        CompliancePublicationResult result = publisherService.publish(request);
        assertThat(result.success()).isTrue();

        // Ensure 2 branches created and 2 branches deleted (1 failed attempt cleaned up + 1 successful attempt cleaned up)
        String shortId = runId.toString().substring(0, 8);
        String targetBranch = "publish/conflict-p-" + shortId;

        long postRefCalls = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .count();
        assertThat(postRefCalls).isEqualTo(2);

        long deleteRefCalls = mockServer.getRecordedRequests().stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains(targetBranch))
                .count();
        assertThat(deleteRefCalls).isEqualTo(2);
    }

    @Test
    @DisplayName("Fault Injection (405 Exhausted): Fails after 3 attempts and cleans up branch on EVERY attempt")
    void testMergeConflict405ExhaustedRetries() {
        mockServer.setSimulateMergeConflict(true); // Persist 405 indefinitely

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Persistent Conflict", "persistent-p", "1.0.0",
                "Vendor", "https://example.com", "MIT", 85, "TEAL_GREEN", 8, 10
        );

        assertThatThrownBy(() -> publisherService.publish(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to publish compliance report after 3 attempts");

        String shortId = runId.toString().substring(0, 8);
        String targetBranch = "publish/persistent-p-" + shortId;

        // Exactly 3 attempts, and exactly 3 branches cleaned up in finally
        long postRefCalls = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .count();
        assertThat(postRefCalls).isEqualTo(3);

        long deleteRefCalls = mockServer.getRecordedRequests().stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains(targetBranch))
                .count();
        assertThat(deleteRefCalls).isEqualTo(3);
    }

    @Test
    @DisplayName("Fault Injection (404): Initial 404 on index.json gracefully initializes catalog without error")
    void testInitialIndexJson404CreatesFreshCatalog() throws Exception {
        mockServer.setExistingIndexJson(null); // Server returns 404 on contents/compliance/index.json

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Initial Product", "init-p", "1.0.0",
                "Vendor", "https://example.com", "Apache-2.0", 95, "EMERALD", 10, 10
        );

        CompliancePublicationResult result = publisherService.publish(request);
        assertThat(result.success()).isTrue();

        // Inspect tree payload to verify compliance/index.json was created with 1 entry
        var treeReq = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/trees"))
                .findFirst().orElseThrow();
        JsonNode treeJson = objectMapper.readTree(treeReq.body());
        String indexContent = null;
        for (JsonNode entry : treeJson.path("tree")) {
            if ("compliance/index.json".equals(entry.path("path").asText())) {
                indexContent = entry.path("content").asText();
            }
        }
        assertThat(indexContent).isNotNull();
        List<ComplianceCatalogEntry> list = objectMapper.readValue(indexContent, new TypeReference<>() {});
        assertThat(list).hasSize(1);
        assertThat(list.get(0).runId()).isEqualTo(runId);
        assertThat(list.get(0).productName()).isEqualTo("Initial Product");
    }

    @Test
    @DisplayName("Fault Injection (401): Authentication failure rejects operation without creating or leaking branches")
    void testAuthenticationFailure401RejectsOperation() {
        mockServer.setSimulateAuthFailure(true);

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Auth Fail Product", "auth-fail", "1.0.0",
                "Vendor", "https://example.com", "Apache-2.0", 90, "EMERALD", 9, 10
        );

        assertThatThrownBy(() -> publisherService.publish(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to exchange GitHub App installation token: HTTP 401");

        // Zero git branches or trees created
        long gitCalls = mockServer.getRecordedRequests().stream()
                .filter(r -> r.path().contains("/git/"))
                .count();
        assertThat(gitCalls).as("Zero git operations should be attempted when auth fails").isZero();
    }

    // =========================================================================
    // 3. MID-FLOW FAULT INJECTION & CLEANUP INVARIANT IN FINALLY
    // =========================================================================

    @Test
    @DisplayName("Cleanup Invariant: Branch deleted in finally when Step 5 (createTree) fails with HTTP 500")
    void testCleanupInvariantWhenCreateTreeFails500() throws Exception {
        runMidFlowFailureTest(5, "Error creating tree: Failed to create tree: HTTP 500");
    }

    @Test
    @DisplayName("Cleanup Invariant: Branch deleted in finally when Step 6 (createCommit) fails with HTTP 500")
    void testCleanupInvariantWhenCreateCommitFails500() throws Exception {
        runMidFlowFailureTest(6, "Error creating commit: Failed to create commit: HTTP 500");
    }

    @Test
    @DisplayName("Cleanup Invariant: Branch deleted in finally when Step 7 (updateBranchRef) fails with HTTP 500")
    void testCleanupInvariantWhenUpdateBranchRefFails500() throws Exception {
        runMidFlowFailureTest(7, "Error updating branch ref");
    }

    @Test
    @DisplayName("Cleanup Invariant: Branch deleted in finally when Step 8 (openPullRequest) fails with HTTP 500")
    void testCleanupInvariantWhenOpenPullRequestFails500() throws Exception {
        runMidFlowFailureTest(8, "Error opening pull request: Failed to open PR: HTTP 500");
    }

    @Test
    @DisplayName("Cleanup Invariant: Branch deleted in finally when Step 9 (squashMerge) fails with HTTP 500 (non-retryable)")
    void testCleanupInvariantWhenSquashMergeFails500() throws Exception {
        runMidFlowFailureTest(9, "Error squash-merging pull request: Failed to squash merge PR");
    }

    private void runMidFlowFailureTest(int failStep, String expectedErrorMessage) throws Exception {
        try (FaultInjectingGitHubServer customServer = new FaultInjectingGitHubServer(failStep)) {
            GitHubAuthService customAuth = new GitHubAuthService(
                    "123456", "78910", pkcs8Pem, customServer.getBaseUrl(), objectMapper, HttpClient.newHttpClient()
            );
            GitHubCompliancePublisherService customPublisher = new GitHubCompliancePublisherService(
                    customAuth, reportGenerator, badgeGenerator, objectMapper, HttpClient.newHttpClient(), customServer.getBaseUrl()
            );
            customPublisher.setEnabled(true);
            customPublisher.setRepo("scimsandbox/scim-website");
            customPublisher.setBranch("main");

            UUID runId = UUID.randomUUID();
            CompliancePublishRequest request = new CompliancePublishRequest(
                    runId, "FaultStep" + failStep, "fault-" + failStep, "1.0.0",
                    "Vendor", "https://example.com", "Apache-2.0", 88, "TEAL_GREEN", 8, 10
            );

            assertThatThrownBy(() -> customPublisher.publish(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining(expectedErrorMessage);

            String shortId = runId.toString().substring(0, 8);
            String targetBranch = "publish/fault-" + failStep + "-" + shortId;

            // Invariant: Because Step 4 (createBranchRef) succeeded, DELETE MUST have been called in finally!
            boolean deleteCalled = customServer.getRecordedRequests().stream()
                    .anyMatch(r -> "DELETE".equals(r.method()) && r.path().contains(targetBranch));
            assertThat(deleteCalled)
                    .as("Temporary branch %s MUST be deleted in finally despite failure at Step %d", targetBranch, failStep)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("Defensive Invariant: Branch deletion failure in finally does NOT mask original workflow exception")
    void testBranchDeletionFailureInFinallyDoesNotMaskOriginalException() throws Exception {
        // Fails Step 5 (createTree) with HTTP 500, AND fails Step 10 (deleteBranchRef) with HTTP 500
        try (FaultInjectingGitHubServer customServer = new FaultInjectingGitHubServer(5, true)) {
            GitHubAuthService customAuth = new GitHubAuthService(
                    "123456", "78910", pkcs8Pem, customServer.getBaseUrl(), objectMapper, HttpClient.newHttpClient()
            );
            GitHubCompliancePublisherService customPublisher = new GitHubCompliancePublisherService(
                    customAuth, reportGenerator, badgeGenerator, objectMapper, HttpClient.newHttpClient(), customServer.getBaseUrl()
            );
            customPublisher.setEnabled(true);
            customPublisher.setRepo("scimsandbox/scim-website");
            customPublisher.setBranch("main");

            UUID runId = UUID.randomUUID();
            CompliancePublishRequest request = new CompliancePublishRequest(
                    runId, "DoubleFault", "double-fault", "1.0.0",
                    "Vendor", "https://example.com", "Apache-2.0", 88, "TEAL_GREEN", 8, 10
            );

            // Caller MUST receive the original Step 5 error, not masked by the failed delete
            assertThatThrownBy(() -> customPublisher.publish(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Error creating tree: Failed to create tree: HTTP 500");

            // But DELETE was still attempted!
            String shortId = runId.toString().substring(0, 8);
            String targetBranch = "publish/double-fault-" + shortId;
            boolean deleteAttempted = customServer.getRecordedRequests().stream()
                    .anyMatch(r -> "DELETE".equals(r.method()) && r.path().contains(targetBranch));
            assertThat(deleteAttempted).isTrue();
        }
    }

    // =========================================================================
    // 4. PRIVATE KEY PEM STRESS & ADVERSARIAL INPUT TESTS
    // =========================================================================

    @Test
    @DisplayName("PEM Stress: Rejects null, blank, and whitespace-only PEM strings")
    void testRejectsNullAndBlankPem() {
        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be null or blank");

        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be null or blank");

        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey("   \n\t  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be null or blank");
    }

    @Test
    @DisplayName("PEM Stress: Rejects invalid Base64 in PEM payload")
    void testRejectsInvalidBase64InPem() {
        String badBase64Pem = "-----BEGIN PRIVATE KEY-----\n!@#$%^&*()_+InvalidBase64\n-----END PRIVATE KEY-----";
        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey(badBase64Pem))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Base64 payload in private key PEM");
    }

    @Test
    @DisplayName("PEM Stress: Rejects valid Base64 with corrupt ASN.1 DER data")
    void testRejectsCorruptDerDataInPem() {
        byte[] randomBytes = new byte[128];
        new Random().nextBytes(randomBytes);
        String corruptDerPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(randomBytes) +
                "\n-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey(corruptDerPem))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Failed to decode RSA private key");
    }

    @Test
    @DisplayName("PEM Stress: Explicitly rejects encrypted PEM keys with actionable guidance")
    void testRejectsEncryptedPem() {
        String encryptedPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI...\n-----END ENCRYPTED PRIVATE KEY-----";
        assertThatThrownBy(() -> GitHubAuthService.parsePemPrivateKey(encryptedPem))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Encrypted RSA private keys are not supported; provide an unencrypted PEM");
    }

    @Test
    @DisplayName("PEM Stress: Correctly parses complex quoted and escaped Kubernetes ConfigMap formatting")
    void testParsesQuotedAndEscapedKubernetesFormatting() {
        // Enclosing double quotes and escaped \n and \r\n
        String k8sFormatted = "\"" + pkcs8Pem.replace("\n", "\\r\\n") + "\"";
        PrivateKey parsed = GitHubAuthService.parsePemPrivateKey(k8sFormatted);
        assertThat(parsed).isNotNull();
        assertThat(parsed.getAlgorithm()).isEqualTo("RSA");

        // Single quotes
        String singleQuoted = "'" + pkcs8Pem.replace("\n", "\\n") + "'";
        PrivateKey parsed2 = GitHubAuthService.parsePemPrivateKey(singleQuoted);
        assertThat(parsed2).isNotNull();
        assertThat(parsed2.getEncoded()).isEqualTo(parsed.getEncoded());
    }

    // =========================================================================
    // HELPER: FAULT-INJECTING HTTP SERVER FOR MID-FLOW ERROR TESTING
    // =========================================================================

    private static class FaultInjectingGitHubServer implements AutoCloseable {
        private final HttpServer server;
        private final int port;
        private final String baseUrl;
        private final ObjectMapper mapper = new ObjectMapper();
        private final List<MockGitHubApiServer.RecordedRequest> recorded = new CopyOnWriteArrayList<>();
        private final int failStep;
        private final boolean failDelete;

        FaultInjectingGitHubServer(int failStep) throws IOException {
            this(failStep, false);
        }

        FaultInjectingGitHubServer(int failStep, boolean failDelete) throws IOException {
            this.failStep = failStep;
            this.failDelete = failDelete;
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            this.server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            this.server.createContext("/", new Handler());
            this.server.start();
            this.port = this.server.getAddress().getPort();
            this.baseUrl = "http://127.0.0.1:" + this.port;
        }

        String getBaseUrl() {
            return baseUrl;
        }

        List<MockGitHubApiServer.RecordedRequest> getRecordedRequests() {
            return Collections.unmodifiableList(recorded);
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private class Handler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();
                String query = exchange.getRequestURI().getQuery();
                Map<String, List<String>> headers = exchange.getRequestHeaders();

                byte[] bodyBytes;
                try (InputStream in = exchange.getRequestBody()) {
                    bodyBytes = in.readAllBytes();
                }
                String body = new String(bodyBytes, StandardCharsets.UTF_8);
                recorded.add(new MockGitHubApiServer.RecordedRequest(method, path, query, headers, body, java.time.Instant.now()));

                // 1. Token Exchange: POST /app/installations/:id/access_tokens
                if ("POST".equalsIgnoreCase(method) && path.matches(".*/app/installations/\\d+/access_tokens")) {
                    sendJson(exchange, 201, Map.of("token", "ghs_fault_mock_token", "expires_at", "2030-01-01T00:00:00Z"));
                    return;
                }

                // 2. Base Branch Ref: GET /repos/:o/:r/git/ref/heads/:branch
                if ("GET".equalsIgnoreCase(method) && path.matches(".*/git/ref/heads/[^/]+")) {
                    sendJson(exchange, 200, Map.of("ref", "refs/heads/main", "object", Map.of("sha", "aa218f56b14c9653891f9e74264a383fa43fefbd", "type", "commit")));
                    return;
                }

                // 3. Base Commit: GET /repos/:o/:r/git/commits/:sha
                if ("GET".equalsIgnoreCase(method) && path.matches(".*/git/commits/[a-f0-9]+")) {
                    sendJson(exchange, 200, Map.of("sha", "aa218f56b14c9653891f9e74264a383fa43fefbd", "tree", Map.of("sha", "6ef19b41225c5369f1c104d45d8d85efa9b057b53b")));
                    return;
                }

                // 4. Index JSON Contents: GET /repos/:o/:r/contents/compliance/index.json
                if ("GET".equalsIgnoreCase(method) && path.endsWith("/contents/compliance/index.json")) {
                    sendJson(exchange, 404, Map.of("message", "Not Found"));
                    return;
                }

                // Step 4: Create Ref / Branch: POST /repos/:o/:r/git/refs
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/refs")) {
                    sendJson(exchange, 201, Map.of("ref", "refs/heads/test", "object", Map.of("sha", "aa218f56b14c9653891f9e74264a383fa43fefbd", "type", "commit")));
                    return;
                }

                // Step 5: Create Tree: POST /repos/:o/:r/git/trees
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/trees")) {
                    if (failStep == 5) {
                        sendJson(exchange, 500, Map.of("message", "Internal Server Error in Tree Service"));
                        return;
                    }
                    sendJson(exchange, 201, Map.of("sha", "tree789"));
                    return;
                }

                // Step 6: Create Commit: POST /repos/:o/:r/git/commits
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/commits")) {
                    if (failStep == 6) {
                        sendJson(exchange, 500, Map.of("message", "Internal Server Error in Commit Service"));
                        return;
                    }
                    sendJson(exchange, 201, Map.of("sha", "commit012"));
                    return;
                }

                // Step 7: Update Branch Ref: PATCH /repos/:o/:r/git/refs/heads/...
                if ("PATCH".equalsIgnoreCase(method) && path.contains("/git/refs/heads/")) {
                    if (failStep == 7) {
                        sendJson(exchange, 500, Map.of("message", "Internal Server Error updating ref"));
                        return;
                    }
                    sendJson(exchange, 200, Map.of("ref", "refs/heads/test", "object", Map.of("sha", "commit012")));
                    return;
                }

                // Step 8: Open Pull Request: POST /repos/:o/:r/pulls
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/pulls")) {
                    if (failStep == 8) {
                        sendJson(exchange, 500, Map.of("message", "Internal Server Error opening PR"));
                        return;
                    }
                    sendJson(exchange, 201, Map.of("number", 99, "html_url", "https://github.com/mock/pr/99"));
                    return;
                }

                // Step 9: Squash Merge: PUT /repos/:o/:r/pulls/:number/merge
                if ("PUT".equalsIgnoreCase(method) && path.matches(".*/pulls/\\d+/merge")) {
                    if (failStep == 9) {
                        sendJson(exchange, 500, Map.of("message", "Internal Server Error during squash merge"));
                        return;
                    }
                    sendJson(exchange, 200, Map.of("sha", "mergedSha", "merged", true));
                    return;
                }

                // Step 10: Delete Branch: DELETE /repos/:o/:r/git/refs/heads/...
                if ("DELETE".equalsIgnoreCase(method) && path.contains("/git/refs/heads/")) {
                    if (failDelete) {
                        sendJson(exchange, 500, Map.of("message", "GitHub internal error deleting ref"));
                        return;
                    }
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                sendJson(exchange, 404, Map.of("message", "Not Found"));
            }

            private void sendJson(HttpExchange exchange, int status, Object body) throws IOException {
                byte[] bytes = mapper.writeValueAsBytes(body);
                exchange.getResponseHeaders().set("Content-Type", "application/vnd.github+json; charset=utf-8");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        }
    }
}
