package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.mock.MockGitHubApiServer;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class GitHubCompliancePublisherServiceTest {

    private MockGitHubApiServer mockServer;
    private GitHubAuthService authService;
    private ComplianceReportGenerator reportGenerator;
    private ComplianceBadgeGenerator badgeGenerator;
    private GitHubCompliancePublisherService publisherService;
    private ObjectMapper objectMapper;

    private KeyPair rsaKeyPair;
    private String pkcs8Pem;
    private String pkcs1Pem;

    @BeforeEach
    void setUp() throws Exception {
        // Generate real 2048-bit RSA key pair for testing genuine RS256 minting and verification
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();

        byte[] pkcs8Bytes = rsaKeyPair.getPrivate().getEncoded();
        pkcs8Pem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs8Bytes) +
                "\n-----END PRIVATE KEY-----";

        // Create genuine PKCS#1 PEM from private key encoding by extracting the inner sequence
        byte[] pkcs1Bytes = extractPkcs1FromPkcs8(pkcs8Bytes);
        pkcs1Pem = "-----BEGIN RSA PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs1Bytes) +
                "\n-----END RSA PRIVATE KEY-----";

        mockServer = new MockGitHubApiServer();
        objectMapper = new ObjectMapper();

        authService = new GitHubAuthService(
                "123456",
                "78910",
                pkcs8Pem,
                mockServer.getBaseUrl(),
                objectMapper,
                HttpClient.newHttpClient()
        );

        badgeGenerator = new ComplianceBadgeGenerator();
        reportGenerator = new ComplianceReportGenerator();

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

    // --- Authentication & RS256 JWT Tests ---

    @Test
    @DisplayName("Should successfully parse PKCS#8 and PKCS#1 PEM keys with unescaped and escaped newlines")
    void shouldParseBothPkcs8AndPkcs1Keys() throws Exception {
        // 1. PKCS#8 standard
        PrivateKey key8 = GitHubAuthService.parsePemPrivateKey(pkcs8Pem);
        assertThat(key8).isNotNull();
        assertThat(key8.getAlgorithm()).isEqualTo("RSA");

        // 2. PKCS#8 with escaped newlines
        String escapedPkcs8 = pkcs8Pem.replace("\n", "\\n");
        PrivateKey key8Escaped = GitHubAuthService.parsePemPrivateKey(escapedPkcs8);
        assertThat(key8Escaped).isNotNull();
        assertThat(key8Escaped.getEncoded()).isEqualTo(key8.getEncoded());

        // 3. PKCS#1 standard
        PrivateKey key1 = GitHubAuthService.parsePemPrivateKey(pkcs1Pem);
        assertThat(key1).isNotNull();
        assertThat(key1.getAlgorithm()).isEqualTo("RSA");

        // 4. PKCS#1 with escaped newlines
        String escapedPkcs1 = pkcs1Pem.replace("\n", "\\n");
        PrivateKey key1Escaped = GitHubAuthService.parsePemPrivateKey(escapedPkcs1);
        assertThat(key1Escaped).isNotNull();
        assertThat(key1Escaped.getEncoded()).isEqualTo(key1.getEncoded());
    }

    @Test
    @DisplayName("Should mint valid RS256 JWT verifiable by RSA public key")
    void shouldMintValidRs256Jwt() throws Exception {
        String jwt = authService.mintJwt();
        assertThat(jwt).isNotNull();
        String[] parts = jwt.split("\\.");
        assertThat(parts).hasSize(3);

        // Verify Header
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        JsonNode headerNode = objectMapper.readTree(headerJson);
        assertThat(headerNode.path("alg").asText()).isEqualTo("RS256");
        assertThat(headerNode.path("typ").asText()).isEqualTo("JWT");

        // Verify Claims
        String claimsJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JsonNode claimsNode = objectMapper.readTree(claimsJson);
        assertThat(claimsNode.path("iss").asText()).isEqualTo("123456");
        assertThat(claimsNode.has("iat")).isTrue();
        assertThat(claimsNode.has("exp")).isTrue();
        assertThat(claimsNode.path("exp").asLong() - claimsNode.path("iat").asLong()).isEqualTo(600L);

        // Verify RS256 Signature with Public Key
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        boolean valid = verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
        assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Should exchange installation token hermetically and cache with safety buffer")
    void shouldExchangeAndCacheInstallationToken() {
        String token1 = authService.getInstallationAccessToken();
        assertThat(token1).startsWith("ghs_mock_installation_token_");

        // Calling second time should return cached token without issuing new HTTP request
        int initialReqCount = mockServer.getRecordedRequests().size();
        String token2 = authService.getInstallationAccessToken();
        assertThat(token2).isEqualTo(token1);
        assertThat(mockServer.getRecordedRequests().size()).isEqualTo(initialReqCount);

        // Invalidate token and verify next call refreshes
        authService.invalidateToken();
        String token3 = authService.getInstallationAccessToken();
        assertThat(token3).isNotNull();
        assertThat(mockServer.getRecordedRequests().size()).isGreaterThan(initialReqCount);
    }

    // --- End-to-End Publication & 10-Step Workflow Tests ---

    @Test
    @DisplayName("Should execute complete 10-step atomic Git publish workflow and clean up branch")
    void shouldPublishReportThroughAll10Steps() throws Exception {
        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId,
                "SCIM Sandbox (Go)",
                "scim-sandbox-go",
                "0.2.11",
                "ScimSandbox Org",
                "https://github.com/scimsandbox/scim-server-go",
                "Apache-2.0",
                true,
                98,
                "EMERALD",
                8,
                10,
                "dev@scimsandbox.net"
        );

        CompliancePublicationResult result = publisherService.publish(request);

        assertThat(result).isNotNull();
        assertThat(result.success()).isTrue();
        assertThat(result.runId()).isEqualTo(runId);
        assertThat(result.prUrl()).contains("/pull/42");
        assertThat(result.reportUrl()).isEqualTo("https://scimsandbox.net/compliance/?run=" + runId);
        assertThat(result.badgeUrl()).isEqualTo("https://scimsandbox.net/compliance/badges/" + runId + ".svg");
        assertThat(result.mergeCommitSha()).isEqualTo("7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f");

        List<MockGitHubApiServer.RecordedRequest> requests = mockServer.getRecordedRequests();
        assertThat(requests).isNotEmpty();

        // 1. Verify headers
        for (var req : requests) {
            if (req.path().contains("/access_tokens")) {
                // Token exchange request carries the minted RS256 JWT
                assertThat(req.getHeader("Authorization")).startsWith("Bearer eyJ");
            } else {
                // Subsequent GitHub Git REST calls carry the exchanged installation access token
                assertThat(req.getHeader("Authorization")).startsWith("Bearer ghs_mock_installation_token_");
            }
            assertThat(req.getHeader("X-GitHub-Api-Version")).isEqualTo("2022-11-28");
            assertThat(req.getHeader("User-Agent")).isEqualTo("scim-validator-ui");
        }

        // 2. Verify Step 4: Branch creation
        var branchReq = requests.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .findFirst().orElseThrow();
        JsonNode branchJson = objectMapper.readTree(branchReq.body());
        String shortId = runId.toString().substring(0, 8);
        assertThat(branchJson.path("ref").asText()).isEqualTo("refs/heads/publish/scim-sandbox-go-" + shortId);

        // 3. Verify Step 5: Tree creation with 4 files and base_tree
        var treeReq = requests.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/trees"))
                .findFirst().orElseThrow();
        JsonNode treeJson = objectMapper.readTree(treeReq.body());
        assertThat(treeJson.path("base_tree").asText()).isEqualTo("6ef19b41225c5369f1c104d45d8d85efa9b057b53b");
        JsonNode treeEntries = treeJson.path("tree");
        assertThat(treeEntries).hasSize(4);

        // Check file paths in tree
        List<String> treePaths = new java.util.ArrayList<>();
        for (JsonNode entry : treeEntries) {
            treePaths.add(entry.path("path").asText());
        }
        assertThat(treePaths).contains(
                "compliance/badges/" + runId + ".svg",
                "compliance/badges/scim-sandbox-go.svg",
                "compliance/index.json"
        );
        assertThat(treePaths.stream().anyMatch(p -> p.startsWith("compliance/reports/scim-sandbox-go/"))).isTrue();

        // 4. Verify Step 6: Commit creation
        var commitReq = requests.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/commits"))
                .findFirst().orElseThrow();
        JsonNode commitJson = objectMapper.readTree(commitReq.body());
        assertThat(commitJson.path("message").asText()).contains("SCIM Sandbox (Go) 0.2.11 scorecard");

        // 5. Verify Step 8: PR creation
        var prReq = requests.stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/pulls"))
                .findFirst().orElseThrow();
        JsonNode prJson = objectMapper.readTree(prReq.body());
        assertThat(prJson.path("head").asText()).isEqualTo("publish/scim-sandbox-go-" + shortId);
        assertThat(prJson.path("base").asText()).isEqualTo("main");

        // 6. Verify Step 9: Squash merge
        var mergeReq = requests.stream()
                .filter(r -> "PUT".equals(r.method()) && r.path().contains("/pulls/42/merge"))
                .findFirst().orElseThrow();
        JsonNode mergeJson = objectMapper.readTree(mergeReq.body());
        assertThat(mergeJson.path("merge_method").asText()).isEqualTo("squash");

        // 7. Verify Step 10: Temporary branch deleted in finally
        var deleteReq = requests.stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains("/git/refs/heads/publish/scim-sandbox-go-" + shortId))
                .findFirst().orElseThrow();
        assertThat(deleteReq).isNotNull();
    }

    // --- Sanitization & Security Assertions (§R3, §R6) ---

    @Test
    @DisplayName("Should guarantee ZERO target URLs, zero bearer tokens, and zero HTTP bodies in committed report")
    void shouldSanitizeCommittedReportPayload() throws Exception {
        UUID runId = UUID.randomUUID();
        String secretTarget = "https://confidential-scim-server.internal:9443/scim/v2";

        ValidationRun run = new ValidationRun();
        org.springframework.test.util.ReflectionTestUtils.setField(run, "id", runId);
        run.setTargetUrl(secretTarget);
        run.setStatus("PASSED");

        ValidationRunPublication pub = new ValidationRunPublication();
        pub.setRun(run);
        pub.setProductName("Internal SCIM Server");
        pub.setProductSlug("internal-scim-server");
        pub.setProductVersion("2.4.0");
        pub.setVendorName("Internal Corp");
        pub.setProjectUrl("https://example.com/project");
        pub.setLicenseType("Commercial");
        pub.setShowSubmitter(false);
        pub.setCreatedByEmail("secret-user@internal.corp");

        ValidationTestResult tr = new ValidationTestResult();
        tr.setTestIdentifier("USR_02");
        tr.setDisplayName("USR_02: Create User");
        tr.setStatus("FAILED");
        tr.setErrorMessage("Connection refused to " + secretTarget + "/Users with header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret");

        ComplianceScorecardView scorecard = new ComplianceScorecardView(
                runId, "Run 1", secretTarget, OffsetDateTime.now(ZoneOffset.UTC), "PASSED",
                95, ColourGradient.EMERALD, true, null,
                null, null, null,
                Collections.emptyList(), 10, 10, 10,
                157, 147, 10, 0,
                Collections.emptyMap(), Collections.emptyList()
        );

        SanitizedComplianceReport report = ComplianceReportGenerator.buildSanitizedReport(
                run, pub, scorecard, List.of(tr)
        );

        String json = objectMapper.writeValueAsString(report);

        // Security Assertions:
        assertThat(json).doesNotContain(secretTarget);
        assertThat(json).doesNotContain("confidential-scim-server.internal");
        assertThat(json).doesNotContain("secret-user@internal.corp");
        assertThat(json).doesNotContain("eyJhbGciOiJIUzI1NiJ9.secret");
        assertThat(json).doesNotContain("\"requestBody\"");
        assertThat(json).doesNotContain("\"responseBody\"");
        assertThat(json).doesNotContain("\"requestHeaders\"");
        assertThat(json).doesNotContain("\"responseHeaders\"");
        assertThat(json).contains("[TARGET_URL]");

        // Verify programmatic assertion passes
        assertThatCode(() -> ComplianceReportGenerator.assertSanitized(json, secretTarget))
                .doesNotThrowAnyException();

        // Verify programmatic assertion fails if target URL is present
        String leakedJson = "{\"target\":\"" + secretTarget + "\"}";
        assertThatThrownBy(() -> ComplianceReportGenerator.assertSanitized(leakedJson, secretTarget))
                .isInstanceOf(SecurityException.class);
    }

    // --- SVG Badge Generation Tests ---

    @Test
    @DisplayName("Should generate valid shields.io compatible SVG badge with exact colour gradient stops")
    void shouldGenerateValidSvgBadges() {
        // Emerald for 100%
        String svgEmerald = badgeGenerator.generate(100, 10, 10, "test1");
        assertThat(svgEmerald).contains("<linearGradient id=\"scim-g-test1\"");
        assertThat(svgEmerald).contains("#10b981");
        assertThat(svgEmerald).contains("#059669");
        assertThat(svgEmerald).contains("100% · 10/10 caps");
        assertThat(svgEmerald).contains("role=\"img\"");
        assertThat(svgEmerald).contains("SCIM 2.0");

        // Amber for 75%
        String svgAmber = badgeGenerator.generate(75, 7, 10, "test2");
        assertThat(svgAmber).contains("#f59e0b");
        assertThat(svgAmber).contains("#d97706");
        assertThat(svgAmber).contains("75% · 7/10 caps");

        // Red for 40%
        String svgRed = badgeGenerator.generate(40, 2, 10, "test3");
        assertThat(svgRed).contains("#ef4444");
        assertThat(svgRed).contains("#dc2626");
        assertThat(svgRed).contains("40% · 2/10 caps");
    }

    // --- Index.json Catalog Update Logic ---

    @Test
    @DisplayName("Should update existing catalog entry in-place or prepend if new")
    void shouldUpdateCatalogEntryProperly() throws Exception {
        UUID run1 = UUID.randomUUID();
        UUID run2 = UUID.randomUUID();

        // Initially index.json does not exist (404)
        mockServer.setExistingIndexJson(null);

        CompliancePublishRequest req1 = new CompliancePublishRequest(
                run1, "Product A", "product-a", "1.0.0", "Vendor A",
                "https://a.dev", "Apache-2.0", 90, "TEAL_GREEN", 9, 10
        );
        publisherService.publish(req1);

        // Capture tree created for run1
        var treeReq1 = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/trees"))
                .findFirst().orElseThrow();
        JsonNode treeJson1 = objectMapper.readTree(treeReq1.body());
        String indexContent1 = null;
        for (JsonNode entry : treeJson1.path("tree")) {
            if ("compliance/index.json".equals(entry.path("path").asText())) {
                indexContent1 = entry.path("content").asText();
            }
        }
        assertThat(indexContent1).isNotNull();
        List<ComplianceCatalogEntry> list1 = objectMapper.readValue(indexContent1, new TypeReference<>() {});
        assertThat(list1).hasSize(1);
        assertThat(list1.get(0).runId()).isEqualTo(run1);

        // Now set server existing index.json to this content and publish run2
        mockServer.setExistingIndexJson(indexContent1);
        CompliancePublishRequest req2 = new CompliancePublishRequest(
                run2, "Product B", "product-b", "2.0.0", "Vendor B",
                "https://b.dev", "MIT", 95, "EMERALD", 10, 10
        );
        publisherService.publish(req2);

        var treeReq2 = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/trees"))
                .skip(1)
                .findFirst().orElseThrow();
        JsonNode treeJson2 = objectMapper.readTree(treeReq2.body());
        String indexContent2 = null;
        for (JsonNode entry : treeJson2.path("tree")) {
            if ("compliance/index.json".equals(entry.path("path").asText())) {
                indexContent2 = entry.path("content").asText();
            }
        }
        assertThat(indexContent2).isNotNull();
        List<ComplianceCatalogEntry> list2 = objectMapper.readValue(indexContent2, new TypeReference<>() {});
        assertThat(list2).hasSize(2);
        // Prepend rule: newest at index 0
        assertThat(list2.get(0).runId()).isEqualTo(run2);
        assertThat(list2.get(1).runId()).isEqualTo(run1);
    }

    // --- Retry & Concurrency Tests ---

    @Test
    @DisplayName("Should retry on merge conflict (405) and succeed when conflict clears on attempt 2")
    void shouldRetryOnMergeConflictAndSucceed() {
        mockServer.setSimulateMergeConflictTimes(1);

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Retry Product", "retry-product", "1.0.0",
                "Org", "https://retry.dev", "Apache-2.0", 85, "TEAL_GREEN", 8, 10
        );

        CompliancePublicationResult result = publisherService.publish(request);
        assertThat(result).isNotNull();
        assertThat(result.success()).isTrue();

        // Ensure branch deletion was called for the failed attempt AND for the successful attempt
        String shortId = runId.toString().substring(0, 8);
        long deleteCount = mockServer.getRecordedRequests().stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains("/refs/heads/publish/retry-product-" + shortId))
                .count();
        assertThat(deleteCount).isEqualTo(2);
    }

    @Test
    @DisplayName("Should throw exception when merge conflicts persist after 3 attempts")
    void shouldFailAfterMaxRetryAttemptsOnPersistentConflict() {
        mockServer.setSimulateMergeConflict(true);

        UUID runId = UUID.randomUUID();
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Persistent Conflict", "persistent-conflict", "1.0.0",
                "Org", "https://conflict.dev", "Apache-2.0", 85, "TEAL_GREEN", 8, 10
        );

        assertThatThrownBy(() -> publisherService.publish(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to publish compliance report after 3 attempts");

        // Verify temporary branch was cleaned up 3 times
        String shortId = runId.toString().substring(0, 8);
        long deleteCount = mockServer.getRecordedRequests().stream()
                .filter(r -> "DELETE".equals(r.method()) && r.path().contains("/refs/heads/publish/persistent-conflict-" + shortId))
                .count();
        assertThat(deleteCount).isEqualTo(3);
    }

    @Test
    @DisplayName("Should throw IllegalStateException when publisher service is disabled")
    void shouldThrowWhenPublisherIsDisabled() {
        publisherService.setEnabled(false);

        CompliancePublishRequest request = new CompliancePublishRequest(
                UUID.randomUUID(), "Disabled Product", "disabled-product", "1.0.0",
                "Org", "https://disabled.dev", "Apache-2.0", 85, "TEAL_GREEN", 8, 10
        );

        assertThatThrownBy(() -> publisherService.publish(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GitHub compliance publishing is disabled by configuration");
    }

    @Test
    @DisplayName("Should validate targetUrl during publish and reject if target host is leaked")
    void shouldRejectPublishWhenTargetHostLeakedInReport() throws Exception {
        UUID runId = UUID.randomUUID();
        String sensitiveTarget = "https://sensitive-target.corp:8443/scim";

        // Setup request with explicit targetUrl
        CompliancePublishRequest request = new CompliancePublishRequest(
                runId, "Leaking Product", "leaking-product", "1.0.0",
                "Vendor", "https://example.com", "MIT", false,
                90, "TEAL_GREEN", 9, 10, null, sensitiveTarget
        );

        // Mock reportGenerator to return a report whose error message contains the sensitive host
        ComplianceReportGenerator mockGenerator = Mockito.mock(ComplianceReportGenerator.class);
        SanitizedComplianceReport leakingReport = new SanitizedComplianceReport(
                SanitizedComplianceReport.SCHEMA_URL,
                SanitizedComplianceReport.CURRENT_SCHEMA_VERSION,
                new SanitizedComplianceReport.ReportMetadata(runId.toString(), "Leaking Product", "leaking-product", "1.0.0", null, null, null, null, null),
                new SanitizedComplianceReport.ReportScorecard(90, ColourGradientInfo.from("TEAL_GREEN", 90), true, null, List.of(), null, null, Map.of(), List.of()),
                List.of(new SanitizedComplianceReport.SanitizedTestResult("test-1", "Test 1", "Class", "test", "FAILED", 100L, "Failed connecting to sensitive-target.corp"))
        );
        when(mockGenerator.generate(any(), any())).thenReturn(leakingReport);

        GitHubCompliancePublisherService publisherWithMock = new GitHubCompliancePublisherService(
                authService,
                mockGenerator,
                badgeGenerator,
                objectMapper,
                HttpClient.newHttpClient(),
                mockServer.getBaseUrl()
        );
        publisherWithMock.setEnabled(true);

        assertThatThrownBy(() -> publisherWithMock.publish(request))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("target host (sensitive-target.corp)");

        // Invariant: ZERO branches created on GitHub when sanitization guard triggers
        long branchCreations = mockServer.getRecordedRequests().stream()
                .filter(r -> "POST".equals(r.method()) && r.path().endsWith("/git/refs"))
                .count();
        assertThat(branchCreations).isEqualTo(0);
    }

    @Test
    @DisplayName("Should resolve targetUrl from ValidationRunRepository when not provided in request")
    void shouldResolveTargetUrlFromRunRepository() {
        UUID runId = UUID.randomUUID();
        ValidationRunRepository mockRepo = Mockito.mock(ValidationRunRepository.class);
        ValidationRun run = new ValidationRun();
        run.setTargetUrl("https://database-resolved-scim.corp:9000");
        when(mockRepo.findById(runId)).thenReturn(Optional.of(run));

        GitHubCompliancePublisherService publisher = new GitHubCompliancePublisherService(
                authService, reportGenerator, badgeGenerator, objectMapper,
                HttpClient.newHttpClient(), mockServer.getBaseUrl(), mockRepo
        );

        CompliancePublishRequest reqWithoutTarget = new CompliancePublishRequest(
                runId, "Test Product", "test-product", "1.0.0",
                "Vendor", "https://example.com", "MIT", 90, "TEAL_GREEN", 9, 10
        );

        String resolved = publisher.resolveTargetUrl(reqWithoutTarget);
        assertThat(resolved).isEqualTo("https://database-resolved-scim.corp:9000");
    }

    @Test
    @DisplayName("Should reject UUID-shaped productSlug and escape Markdown table cells and @mentions in PR body")
    void shouldRejectUuidProductSlugAndEscapeMarkdownInPrBody() {
        UUID runId = UUID.randomUUID();
        CompliancePublishRequest uuidSlugReq = new CompliancePublishRequest(
                runId, "Test Product", runId.toString(), "1.0.0",
                "Vendor", "https://example.com", "MIT", 90, "TEAL_GREEN", 9, 10
        );

        assertThatThrownBy(() -> publisherService.publish(uuidSlugReq))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UUID-formatted slugs are reserved");

        CompliancePublishRequest markdownReq = new CompliancePublishRequest(
                runId, "Prod | Name\nRow2 @admin #1", "prod-name", "1.0.0",
                "Vendor <script> | @org", "https://example.com/a|b", "MIT", 90, "TEAL_GREEN", 9, 10
        );
        String prBody = publisherService.generatePrBody(
                markdownReq,
                OffsetDateTime.now(ZoneOffset.UTC)
        );
        assertThat(prBody).contains("Prod \\| Name Row2 @\u200Badmin #\u200B1");
        assertThat(prBody).contains("Vendor &lt;script&gt; \\| @\u200Borg");
        assertThat(prBody).doesNotContain("@admin");
        assertThat(prBody).doesNotContain("<script>");
    }

    private static byte[] extractPkcs1FromPkcs8(byte[] pkcs8Der) {
        // Simple ASN.1 extractor for RSA Private Key OCTET STRING within PKCS#8 PrivateKeyInfo
        // In PKCS#8: SEQUENCE { version INTEGER, alg AlgorithmIdentifier, privateKey OCTET STRING }
        // The last component is the OCTET STRING containing the raw PKCS#1 DER bytes.
        int idx = 0;
        if (pkcs8Der[idx++] != 0x30) throw new IllegalArgumentException("Not a SEQUENCE");
        idx = skipDerLength(pkcs8Der, idx);
        // version: INTEGER 0
        if (pkcs8Der[idx++] != 0x02) throw new IllegalArgumentException("Not an INTEGER");
        int vLen = pkcs8Der[idx++];
        idx += vLen;
        // AlgorithmIdentifier: SEQUENCE
        if (pkcs8Der[idx++] != 0x30) throw new IllegalArgumentException("Not an Algo SEQUENCE");
        int aLen = getDerLength(pkcs8Der, idx);
        idx = skipDerLength(pkcs8Der, idx);
        idx += aLen;
        // privateKey: OCTET STRING (0x04)
        if (pkcs8Der[idx++] != 0x04) throw new IllegalArgumentException("Not an OCTET STRING");
        int octetLen = getDerLength(pkcs8Der, idx);
        idx = skipDerLength(pkcs8Der, idx);

        byte[] pkcs1 = new byte[octetLen];
        System.arraycopy(pkcs8Der, idx, pkcs1, 0, octetLen);
        return pkcs1;
    }

    private static int skipDerLength(byte[] der, int offset) {
        int b = der[offset++] & 0xff;
        if (b < 128) return offset;
        int numBytes = b & 0x7f;
        return offset + numBytes;
    }

    private static int getDerLength(byte[] der, int offset) {
        int b = der[offset++] & 0xff;
        if (b < 128) return b;
        int numBytes = b & 0x7f;
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | (der[offset++] & 0xff);
        }
        return len;
    }
}
