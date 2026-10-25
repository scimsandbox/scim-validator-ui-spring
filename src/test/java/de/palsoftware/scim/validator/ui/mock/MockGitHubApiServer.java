package de.palsoftware.scim.validator.ui.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * Hermetic mock HTTP server simulating GitHub REST API endpoints
 * required for 1-click compliance publishing (ORIGINAL_REQUEST §R6).
 */
public class MockGitHubApiServer implements AutoCloseable {

    private final HttpServer server;
    private final int port;
    private final String baseUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<RecordedRequest> recordedRequests = new CopyOnWriteArrayList<>();

    // Mock State Configuration
    private String baseCommitSha = "aa218f56b14c9653891f9e74264a383fa43fefbd";
    private String baseTreeSha = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b";
    private String createdTreeSha = "9fb976ba1812add43ab62ea977000865120e932b";
    private String createdCommitSha = "4a5b6c7d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b";
    private String squashMergeSha = "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f";
    private int nextPullNumber = 42;
    private String existingIndexJsonContent = null; // null => returns 404
    private boolean simulateMergeConflict = false;
    private int mergeConflictRemainingCount = 0;
    private int mergeConflictStatusCode = 405;
    private int branchUpdateConflictStatusCode = 0;
    private int branchUpdateConflictRemainingCount = 0;
    private boolean simulateBranchExists = false;
    private boolean simulateAuthFailure = false;

    public record RecordedRequest(
            String method,
            String path,
            String query,
            Map<String, List<String>> headers,
            String body,
            Instant timestamp
    ) {
        public String getHeader(String name) {
            if (headers == null || name == null) return null;
            for (var entry : headers.entrySet()) {
                if (name.equalsIgnoreCase(entry.getKey())) {
                    return entry.getValue() != null && !entry.getValue().isEmpty()
                            ? entry.getValue().get(0)
                            : null;
                }
            }
            return null;
        }
    }

    public MockGitHubApiServer() throws IOException {
        // Ephemeral port binding on localhost
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        this.server.createContext("/", new GitHubDispatcher());
        this.server.start();
        this.port = this.server.getAddress().getPort();
        this.baseUrl = "http://127.0.0.1:" + this.port;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public int getPort() {
        return port;
    }

    public List<RecordedRequest> getRecordedRequests() {
        return Collections.unmodifiableList(recordedRequests);
    }

    public void reset() {
        recordedRequests.clear();
        simulateMergeConflict = false;
        mergeConflictRemainingCount = 0;
        mergeConflictStatusCode = 405;
        branchUpdateConflictStatusCode = 0;
        branchUpdateConflictRemainingCount = 0;
        simulateBranchExists = false;
        simulateAuthFailure = false;
        existingIndexJsonContent = null;
    }

    public void setExistingIndexJson(String json) {
        this.existingIndexJsonContent = json;
    }

    public void setSimulateMergeConflict(boolean conflict) {
        setSimulateMergeConflict(conflict, 405);
    }

    public void setSimulateMergeConflict(boolean conflict, int statusCode) {
        this.simulateMergeConflict = conflict;
        this.mergeConflictRemainingCount = conflict ? Integer.MAX_VALUE : 0;
        this.mergeConflictStatusCode = statusCode;
    }

    public void setSimulateMergeConflictTimes(int times) {
        setSimulateMergeConflictTimes(times, 405);
    }

    public void setSimulateMergeConflictTimes(int times, int statusCode) {
        this.simulateMergeConflict = times > 0;
        this.mergeConflictRemainingCount = times;
        this.mergeConflictStatusCode = statusCode;
    }

    public void setSimulateBranchUpdateConflict(int statusCode, int times) {
        this.branchUpdateConflictStatusCode = statusCode;
        this.branchUpdateConflictRemainingCount = times;
    }

    public void setSimulateBranchExists(boolean exists) {
        this.simulateBranchExists = exists;
    }

    public void setSimulateAuthFailure(boolean authFailure) {
        this.simulateAuthFailure = authFailure;
    }

    public void setBaseCommitSha(String sha) {
        this.baseCommitSha = sha;
    }

    public void setBaseTreeSha(String sha) {
        this.baseTreeSha = sha;
    }

    public void setCreatedTreeSha(String sha) {
        this.createdTreeSha = sha;
    }

    public void setCreatedCommitSha(String sha) {
        this.createdCommitSha = sha;
    }

    public void setSquashMergeSha(String sha) {
        this.squashMergeSha = sha;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private class GitHubDispatcher implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();
                String query = exchange.getRequestURI().getQuery();
                Map<String, List<String>> headers = exchange.getRequestHeaders();

                byte[] bodyBytes;
                try (InputStream in = exchange.getRequestBody()) {
                    bodyBytes = in.readAllBytes();
                }
                String body = new String(bodyBytes, StandardCharsets.UTF_8);

                recordedRequests.add(new RecordedRequest(method, path, query, headers, body, Instant.now()));

                if (simulateAuthFailure) {
                    sendJson(exchange, 401, Map.of("message", "Bad credentials"));
                    return;
                }

                // 1. Installation Token Exchange: POST /app/installations/:id/access_tokens
                if ("POST".equalsIgnoreCase(method) && path.matches(".*/app/installations/\\d+/access_tokens")) {
                    sendJson(exchange, 201, Map.of(
                            "token", "ghs_mock_installation_token_" + System.currentTimeMillis(),
                            "expires_at", "2030-01-01T00:00:00Z"
                    ));
                    return;
                }

                // 2. Base Branch Ref: GET /repos/:o/:r/git/ref/heads/:branch
                if ("GET".equalsIgnoreCase(method) && path.matches(".*/git/ref/heads/[^/]+")) {
                    String refPart = path.substring(path.indexOf("heads/"));
                    sendJson(exchange, 200, Map.of(
                            "ref", "refs/" + refPart,
                            "object", Map.of(
                                    "sha", baseCommitSha,
                                    "type", "commit"
                            )
                    ));
                    return;
                }

                // 3. Base Commit: GET /repos/:o/:r/git/commits/:sha
                if ("GET".equalsIgnoreCase(method) && path.matches(".*/git/commits/[a-f0-9]+")) {
                    sendJson(exchange, 200, Map.of(
                            "sha", baseCommitSha,
                            "tree", Map.of("sha", baseTreeSha)
                    ));
                    return;
                }

                // 4. Index JSON Contents: GET /repos/:o/:r/contents/compliance/index.json
                if ("GET".equalsIgnoreCase(method) && path.endsWith("/contents/compliance/index.json")) {
                    if (existingIndexJsonContent == null) {
                        sendJson(exchange, 404, Map.of("message", "Not Found"));
                    } else {
                        String b64 = Base64.getEncoder().encodeToString(existingIndexJsonContent.getBytes(StandardCharsets.UTF_8));
                        sendJson(exchange, 200, Map.of(
                                "type", "file",
                                "encoding", "base64",
                                "content", b64,
                                "path", "compliance/index.json"
                        ));
                    }
                    return;
                }

                // 5. Create Ref / Branch: POST /repos/:o/:r/git/refs
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/refs")) {
                    if (simulateBranchExists) {
                        // simulate branch already existing once then cleared
                        simulateBranchExists = false;
                        sendJson(exchange, 422, Map.of("message", "Reference already exists"));
                        return;
                    }
                    JsonNode node = objectMapper.readTree(body);
                    String ref = node.path("ref").asText();
                    String sha = node.path("sha").asText();
                    sendJson(exchange, 201, Map.of(
                            "ref", ref,
                            "object", Map.of("sha", sha, "type", "commit")
                    ));
                    return;
                }

                // 6. Create Tree: POST /repos/:o/:r/git/trees
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/trees")) {
                    sendJson(exchange, 201, Map.of(
                            "sha", createdTreeSha,
                            "url", baseUrl + path + "/" + createdTreeSha
                    ));
                    return;
                }

                // 7. Create Commit: POST /repos/:o/:r/git/commits
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/git/commits")) {
                    sendJson(exchange, 201, Map.of(
                            "sha", createdCommitSha,
                            "url", baseUrl + path + "/" + createdCommitSha
                    ));
                    return;
                }

                // 8. Update Branch Ref: PATCH /repos/:o/:r/git/refs/heads/...
                if ("PATCH".equalsIgnoreCase(method) && path.contains("/git/refs/heads/")) {
                    if (branchUpdateConflictStatusCode > 0 && branchUpdateConflictRemainingCount > 0) {
                        branchUpdateConflictRemainingCount--;
                        sendJson(exchange, branchUpdateConflictStatusCode, Map.of("message", "Branch ref update conflict"));
                        return;
                    }
                    sendJson(exchange, 200, Map.of(
                            "ref", "refs/heads/publish/...",
                            "object", Map.of("sha", createdCommitSha)
                    ));
                    return;
                }

                // 9. Open Pull Request: POST /repos/:o/:r/pulls
                if ("POST".equalsIgnoreCase(method) && path.endsWith("/pulls")) {
                    int pullNum = nextPullNumber++;
                    sendJson(exchange, 201, Map.of(
                            "id", 1000 + pullNum,
                            "number", pullNum,
                            "html_url", "https://github.com/scimsandbox/scim-website/pull/" + pullNum,
                            "state", "open"
                    ));
                    return;
                }

                // 10. Squash Merge Pull Request: PUT /repos/:o/:r/pulls/:number/merge
                if ("PUT".equalsIgnoreCase(method) && path.matches(".*/pulls/\\d+/merge")) {
                    if (simulateMergeConflict && mergeConflictRemainingCount > 0) {
                        mergeConflictRemainingCount--;
                        if (mergeConflictRemainingCount == 0) {
                            simulateMergeConflict = false;
                        }
                        sendJson(exchange, mergeConflictStatusCode, Map.of("message", "Pull Request is not mergeable"));
                        return;
                    }
                    sendJson(exchange, 200, Map.of(
                            "sha", squashMergeSha,
                            "merged", true,
                            "message", "Pull Request successfully merged"
                    ));
                    return;
                }

                // 11. Delete Temporary Branch: DELETE /repos/:o/:r/git/refs/heads/...
                if ("DELETE".equalsIgnoreCase(method) && path.contains("/git/refs/heads/")) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                // Fallback for unexpected paths
                sendJson(exchange, 404, Map.of("message", "Unhandled mock path: " + path));
            } catch (Exception ex) {
                sendJson(exchange, 500, Map.of("error", ex.getMessage()));
            }
        }

        private void sendJson(HttpExchange exchange, int statusCode, Object body) throws IOException {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            exchange.getResponseHeaders().set("Content-Type", "application/vnd.github+json; charset=utf-8");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
