package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.spec.*;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class GitHubCompliancePublisherService {

    private static final Logger log = LoggerFactory.getLogger(GitHubCompliancePublisherService.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final GitHubAuthService authService;
    private final ComplianceReportGenerator reportGenerator;
    private final ComplianceBadgeGenerator badgeGenerator;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final ValidationRunRepository runRepository;
    private final ReentrantLock publishLock = new ReentrantLock(true);

    @Value("${app.github.publish.enabled:${app.github.publish-enabled:false}}")
    private boolean enabled = false;

    @Value("${app.github.app-id:${app.github.app_id:}}")
    private String appId;

    @Value("${app.github.installation-id:${app.github.installation_id:}}")
    private String installationId;

    @Value("${app.github.private-key:${app.github.private_key:}}")
    private String privateKey;

    @Value("${app.github.repo:scimsandbox/scim-website}")
    private String repo = "scimsandbox/scim-website";

    @Value("${app.github.branch:main}")
    private String branch = "main";

    @Value("${app.github.api-url:${app.github.api-base-url:https://api.github.com}}")
    private String apiUrl = "https://api.github.com";

    public static class GitHubMergeConflictException extends RuntimeException {
        public GitHubMergeConflictException(String message) {
            super(message);
        }
    }

    public GitHubCompliancePublisherService(
            GitHubAuthService authService,
            ComplianceReportGenerator reportGenerator,
            ComplianceBadgeGenerator badgeGenerator) {
        this(authService, reportGenerator, badgeGenerator, new ObjectMapper(), HttpClient.newHttpClient(), null, null);
    }

    public GitHubCompliancePublisherService(
            GitHubAuthService authService,
            ComplianceReportGenerator reportGenerator,
            ComplianceBadgeGenerator badgeGenerator,
            ObjectMapper objectMapper,
            HttpClient httpClient,
            String apiUrl) {
        this(authService, reportGenerator, badgeGenerator, objectMapper, httpClient, apiUrl, null);
    }

    @Autowired
    public GitHubCompliancePublisherService(
            GitHubAuthService authService,
            ComplianceReportGenerator reportGenerator,
            ComplianceBadgeGenerator badgeGenerator,
            ObjectMapper objectMapper,
            @Autowired(required = false) HttpClient httpClient,
            @Value("${app.github.api-url:${app.github.api-base-url:https://api.github.com}}") String apiUrl,
            @Autowired(required = false) ValidationRunRepository runRepository) {
        this.authService = authService;
        this.reportGenerator = reportGenerator;
        this.badgeGenerator = badgeGenerator;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        if (apiUrl != null && !apiUrl.isBlank()) {
            this.apiUrl = apiUrl;
        }
        this.runRepository = runRepository;
    }

    String resolveTargetUrl(CompliancePublishRequest req) {
        if (req != null && req.targetUrl() != null && !req.targetUrl().isBlank()) {
            return req.targetUrl();
        }
        if (runRepository != null && req != null && req.runId() != null) {
            try {
                return runRepository.findById(req.runId())
                        .map(ValidationRun::getTargetUrl)
                        .orElse(null);
            } catch (Exception e) {
                log.warn("Could not query ValidationRun for targetUrl resolution (runId={}): {}", req.runId(), e.getMessage());
            }
        }
        return null;
    }

    public CompliancePublicationResult publish(CompliancePublishRequest request) {
        if (!enabled) {
            throw new IllegalStateException("GitHub compliance publishing is disabled by configuration");
        }

        publishLock.lock();
        try {
            return executePublishWithRetry(request, 3);
        } finally {
            publishLock.unlock();
        }
    }

    private CompliancePublicationResult executePublishWithRetry(CompliancePublishRequest request, int maxAttempts) {
        int attempt = 0;
        while (attempt < maxAttempts) {
            attempt++;
            try {
                return doPublishWorkflow(request);
            } catch (GitHubMergeConflictException e) {
                log.warn("Publish attempt {}/{} failed due to merge conflict: {}", attempt, maxAttempts, e.getMessage());
                if (attempt >= maxAttempts) {
                    throw new RuntimeException("Failed to publish compliance report after " + maxAttempts + " attempts: " + e.getMessage(), e);
                }
                try {
                    Thread.sleep(500L + (long) (Math.random() * 250));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Publish retry interrupted", ie);
                }
            }
        }
        throw new RuntimeException("Failed to publish compliance report after " + maxAttempts + " attempts");
    }

    private CompliancePublicationResult doPublishWorkflow(CompliancePublishRequest req) {
        String token = authService.getInstallationAccessToken();
        UUID runId = req.runId();
        String shortRunId = runId.toString().substring(0, 8);
        String branchName = "publish/" + req.productSlug() + "-" + shortRunId;
        String branchRef = "refs/heads/" + branchName;
        OffsetDateTime publishedAt = OffsetDateTime.now(ZoneOffset.UTC);

        // Step 1: Fetch HEAD of base branch ref
        String baseCommitSha = fetchBaseCommitSha(token);

        // Step 2: Fetch commit's tree SHA
        String baseTreeSha = fetchCommitTreeSha(token, baseCommitSha);

        // Step 3: Fetch existing compliance/index.json
        List<ComplianceCatalogEntry> catalog = fetchExistingCatalog(token);

        // Generate file paths and contents
        String dateSlug = publishedAt.format(DATE_FORMATTER);
        String reportPath = String.format("compliance/reports/%s/%s-%s-%s.json",
                req.productSlug(), req.productVersion(), dateSlug, runId);
        String runBadgePath = String.format("compliance/badges/%s.svg", runId);
        String productBadgePath = String.format("compliance/badges/%s.svg", req.productSlug());
        String indexPath = "compliance/index.json";

        SanitizedComplianceReport sanitizedReport = reportGenerator.generate(req, publishedAt);
        String reportJson;
        try {
            reportJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(sanitizedReport) + "\n";
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize sanitized compliance report", e);
        }

        // Programmatic security assertion ensuring ZERO target URLs or credentials leaked
        String targetUrl = resolveTargetUrl(req);
        ComplianceReportGenerator.assertSanitized(reportJson, targetUrl);

        String runBadgeSvg = badgeGenerator.generate(req.coreScore(), req.supportedCapabilities(), req.totalCapabilities(), shortRunId);
        String productBadgeSvg = badgeGenerator.generate(req.coreScore(), req.supportedCapabilities(), req.totalCapabilities(), req.productSlug());

        // Update catalog in-memory
        ComplianceCatalogEntry newEntry = new ComplianceCatalogEntry(
                runId,
                req.productName(),
                req.productSlug(),
                req.productVersion(),
                req.vendorName(),
                req.projectUrl(),
                req.licenseType(),
                req.coreScore(),
                ColourGradientInfo.from(req.colourGradient(), req.coreScore()),
                req.supportedCapabilities(),
                req.totalCapabilities(),
                reportPath,
                productBadgePath,
                publishedAt
        );

        int existingIndex = -1;
        for (int i = 0; i < catalog.size(); i++) {
            ComplianceCatalogEntry entry = catalog.get(i);
            if (Objects.equals(entry.runId(), runId)) {
                existingIndex = i;
                break;
            }
        }
        if (existingIndex >= 0) {
            catalog.set(existingIndex, newEntry);
        } else {
            catalog.add(0, newEntry);
        }

        String indexJson;
        try {
            indexJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(catalog) + "\n";
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize compliance index.json", e);
        }

        boolean branchCreated = false;
        try {
            // Step 4: Create temporary branch at baseCommitSha
            createBranchRef(token, branchRef, baseCommitSha);
            branchCreated = true;

            // Step 5: Create tree with 4 files pointing to base_tree
            List<Map<String, Object>> treeEntries = List.of(
                    Map.of("path", reportPath, "mode", "100644", "type", "blob", "content", reportJson),
                    Map.of("path", runBadgePath, "mode", "100644", "type", "blob", "content", runBadgeSvg),
                    Map.of("path", productBadgePath, "mode", "100644", "type", "blob", "content", productBadgeSvg),
                    Map.of("path", indexPath, "mode", "100644", "type", "blob", "content", indexJson)
            );
            String newTreeSha = createTree(token, baseTreeSha, treeEntries);

            // Step 6: Create commit
            String commitMsg = String.format("publish(compliance): %s %s scorecard (%s)",
                    req.productName(), req.productVersion(), runId);
            String newCommitSha = createCommit(token, commitMsg, newTreeSha, List.of(baseCommitSha));

            // Step 7: Update branch ref
            updateBranchRef(token, branchName, newCommitSha);

            // Step 8: Open Pull Request
            String prTitle = String.format("publish(compliance): %s %s (%s)",
                    req.productName(), req.productVersion(), shortRunId);
            String prBody = generatePrBody(req, publishedAt);
            JsonNode prResponse = openPullRequest(token, prTitle, branchName, branch, prBody);
            int pullNumber = prResponse.get("number").asInt();
            String prUrl = prResponse.get("html_url").asText();

            // Step 9: Squash-merge Pull Request
            String mergeCommitTitle = String.format("publish(compliance): %s %s scorecard (#%d)",
                    req.productName(), req.productVersion(), pullNumber);
            String mergeCommitSha = squashMergePullRequest(token, pullNumber, mergeCommitTitle, prBody);

            String reportUrl = "https://scimsandbox.net/compliance/?run=" + runId;
            String badgeUrl = "https://scimsandbox.net/" + runBadgePath;

            return CompliancePublicationResult.success(runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, publishedAt);
        } finally {
            // Step 10: Delete temporary branch (guaranteed cleanup)
            if (branchCreated) {
                try {
                    deleteBranchRef(token, branchName);
                } catch (Exception ex) {
                    log.warn("Failed to delete temporary branch {}", branchName, ex);
                }
            }
        }
    }

    private String getEffectiveApiUrl() {
        String url = apiUrl != null && !apiUrl.isBlank() ? apiUrl : "https://api.github.com";
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private HttpRequest.Builder newRequestBuilder(String path, String token) {
        String base = getEffectiveApiUrl();
        String cleanPath = path.startsWith("/") ? path : "/" + path;
        return HttpRequest.newBuilder()
                .uri(URI.create(base + cleanPath))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "scim-validator-ui")
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15));
    }

    private String fetchBaseCommitSha(String token) {
        String path = "/repos/" + repo + "/git/ref/heads/" + branch;
        HttpRequest request = newRequestBuilder(path, token).GET().build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Failed to fetch base branch ref: HTTP " + response.statusCode() + " " + response.body());
            }
            JsonNode root = objectMapper.readTree(response.body());
            return root.path("object").path("sha").asText();
        } catch (Exception e) {
            throw new RuntimeException("Error fetching base branch ref: " + e.getMessage(), e);
        }
    }

    private String fetchCommitTreeSha(String token, String commitSha) {
        String path = "/repos/" + repo + "/git/commits/" + commitSha;
        HttpRequest request = newRequestBuilder(path, token).GET().build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Failed to fetch commit tree: HTTP " + response.statusCode() + " " + response.body());
            }
            JsonNode root = objectMapper.readTree(response.body());
            return root.path("tree").path("sha").asText();
        } catch (Exception e) {
            throw new RuntimeException("Error fetching commit tree: " + e.getMessage(), e);
        }
    }

    private List<ComplianceCatalogEntry> fetchExistingCatalog(String token) {
        String path = "/repos/" + repo + "/contents/compliance/index.json?ref=" + branch;
        HttpRequest request = newRequestBuilder(path, token).GET().build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                return new ArrayList<>();
            }
            if (response.statusCode() != 200) {
                log.warn("Non-200 fetching index.json (HTTP {}), defaulting to empty catalog", response.statusCode());
                return new ArrayList<>();
            }
            JsonNode root = objectMapper.readTree(response.body());
            String content = root.path("content").asText(null);
            if (content == null || content.isBlank()) {
                return new ArrayList<>();
            }
            byte[] decoded = Base64.getMimeDecoder().decode(content);
            String decodedStr = new String(decoded, StandardCharsets.UTF_8);
            List<ComplianceCatalogEntry> entries = objectMapper.readValue(decodedStr,
                    new TypeReference<List<ComplianceCatalogEntry>>() {});
            return entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        } catch (Exception e) {
            log.warn("Error reading compliance/index.json: {}, starting with empty catalog", e.getMessage());
            return new ArrayList<>();
        }
    }

    private void createBranchRef(String token, String branchRef, String baseSha) {
        String path = "/repos/" + repo + "/git/refs";
        Map<String, String> payload = Map.of(
                "ref", branchRef,
                "sha", baseSha
        );
        try {
            String body = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 422) {
                // If branch reference already exists from prior run, delete and recreate
                log.warn("Branch ref {} already exists, attempting to delete and recreate", branchRef);
                String subName = branchRef.replace("refs/heads/", "");
                deleteBranchRef(token, subName);
                HttpResponse<String> retryResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (retryResponse.statusCode() != 201) {
                    throw new IllegalStateException("Failed to create branch ref after retry: HTTP " + retryResponse.statusCode() + " " + retryResponse.body());
                }
                return;
            }
            if (response.statusCode() != 201) {
                throw new IllegalStateException("Failed to create branch ref: HTTP " + response.statusCode() + " " + response.body());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error creating branch ref " + branchRef + ": " + e.getMessage(), e);
        }
    }

    private String createTree(String token, String baseTreeSha, List<Map<String, Object>> entries) {
        String path = "/repos/" + repo + "/git/trees";
        Map<String, Object> payload = Map.of(
                "base_tree", baseTreeSha,
                "tree", entries
        );
        try {
            String body = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                throw new IllegalStateException("Failed to create tree: HTTP " + response.statusCode() + " " + response.body());
            }
            JsonNode root = objectMapper.readTree(response.body());
            return root.path("sha").asText();
        } catch (Exception e) {
            throw new RuntimeException("Error creating tree: " + e.getMessage(), e);
        }
    }

    private String createCommit(String token, String message, String treeSha, List<String> parents) {
        String path = "/repos/" + repo + "/git/commits";
        Map<String, Object> payload = Map.of(
                "message", message,
                "tree", treeSha,
                "parents", parents
        );
        try {
            String body = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                throw new IllegalStateException("Failed to create commit: HTTP " + response.statusCode() + " " + response.body());
            }
            JsonNode root = objectMapper.readTree(response.body());
            return root.path("sha").asText();
        } catch (Exception e) {
            throw new RuntimeException("Error creating commit: " + e.getMessage(), e);
        }
    }

    private void updateBranchRef(String token, String branchName, String newCommitSha) {
        String path = "/repos/" + repo + "/git/refs/heads/" + branchName;
        Map<String, Object> payload = Map.of(
                "sha", newCommitSha,
                "force", false
        );
        try {
            String body = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .method("PATCH", HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Failed to update branch ref: HTTP " + response.statusCode() + " " + response.body());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error updating branch ref " + branchName + ": " + e.getMessage(), e);
        }
    }

    private JsonNode openPullRequest(String token, String title, String headBranch, String baseBranch, String body) {
        String path = "/repos/" + repo + "/pulls";
        Map<String, String> payload = Map.of(
                "title", title,
                "head", headBranch,
                "base", baseBranch,
                "body", body
        );
        try {
            String requestBody = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                throw new IllegalStateException("Failed to open PR: HTTP " + response.statusCode() + " " + response.body());
            }
            return objectMapper.readTree(response.body());
        } catch (Exception e) {
            throw new RuntimeException("Error opening pull request: " + e.getMessage(), e);
        }
    }

    private String squashMergePullRequest(String token, int pullNumber, String commitTitle, String commitMessage) {
        String path = "/repos/" + repo + "/pulls/" + pullNumber + "/merge";
        Map<String, String> payload = Map.of(
                "commit_title", commitTitle,
                "commit_message", commitMessage,
                "merge_method", "squash"
        );
        try {
            String requestBody = objectMapper.writeValueAsString(payload);
            HttpRequest request = newRequestBuilder(path, token)
                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 405 || response.statusCode() == 409) {
                throw new GitHubMergeConflictException("Pull request #" + pullNumber + " cannot be merged (HTTP " + response.statusCode() + "): " + response.body());
            }
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Failed to squash merge PR #" + pullNumber + ": HTTP " + response.statusCode() + " " + response.body());
            }
            JsonNode root = objectMapper.readTree(response.body());
            boolean merged = root.path("merged").asBoolean(false);
            if (!merged) {
                throw new GitHubMergeConflictException("Merge response indicated merged=false: " + response.body());
            }
            return root.path("sha").asText();
        } catch (GitHubMergeConflictException ce) {
            throw ce;
        } catch (Exception e) {
            throw new RuntimeException("Error squash-merging pull request: " + e.getMessage(), e);
        }
    }

    private void deleteBranchRef(String token, String branchName) {
        String path = "/repos/" + repo + "/git/refs/heads/" + branchName;
        HttpRequest request = newRequestBuilder(path, token)
                .DELETE()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 204 && response.statusCode() != 404) {
                log.warn("Unexpected status code {} deleting branch ref {}", response.statusCode(), branchName);
            }
        } catch (Exception e) {
            log.warn("Error deleting branch ref {}: {}", branchName, e.getMessage());
        }
    }

    private String generatePrBody(CompliancePublishRequest req, OffsetDateTime publishedAt) {
        String publishedAtStr = publishedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        return String.format("""
## SCIM 2.0 Compliance Publication

| Attribute | Value |
|---|---|
| **Product** | %s |
| **Version** | %s |
| **Vendor / Org** | %s |
| **Core Conformance** | **%d%%** (%s) |
| **Capabilities** | %d/%d |
| **Run ID** | `%s` |
| **Published At** | %s |

*Automated publication by SCIM Compliance Validator (`val.scimsandbox.net`).*
""",
                req.productName() != null ? req.productName() : "N/A",
                req.productVersion() != null ? req.productVersion() : "N/A",
                req.vendorName() != null ? req.vendorName() : "N/A",
                req.coreScore(),
                req.colourGradient() != null ? req.colourGradient() : "N/A",
                req.supportedCapabilities(),
                req.totalCapabilities(),
                req.runId(),
                publishedAtStr
        );
    }

    // Getters and setters for testing
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRepo() {
        return repo;
    }

    public void setRepo(String repo) {
        this.repo = repo;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }
}
