package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class GitHubAuthService {

    private static final Logger log = LoggerFactory.getLogger(GitHubAuthService.class);

    private static final byte[] RSA_ALGO_IDENTIFIER = new byte[]{
            0x30, 0x0d,
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00
    };

    private static final String JWT_HEADER_B64 = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

    private static final Duration EXPIRATION_BUFFER = Duration.ofMinutes(5);

    @Value("${app.github.publish.enabled:${app.github.publish-enabled:false}}")
    private boolean publishEnabled = false;

    @Value("${app.github.app-id:${app.github.app_id:}}")
    private String appId;

    @Value("${app.github.installation-id:${app.github.installation_id:}}")
    private String installationId;

    @Value("${app.github.private-key:${app.github.private_key:}}")
    private String privateKey;

    @Value("${app.github.api-url:${app.github.api-base-url:https://api.github.com}}")
    private String apiUrl = "https://api.github.com";

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final Object tokenLock = new Object();

    private volatile PrivateKey cachedPrivateKey;
    private volatile CachedToken cachedToken;

    public record CachedToken(String token, Instant expiresAt) {
        public boolean isValid() {
            return token != null && !token.isBlank() && expiresAt != null &&
                    Instant.now().plus(EXPIRATION_BUFFER).isBefore(expiresAt);
        }
    }

    @Autowired
    public GitHubAuthService() {
        this(new ObjectMapper(), HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build());
    }

    public GitHubAuthService(ObjectMapper objectMapper) {
        this(objectMapper, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build());
    }

    public GitHubAuthService(ObjectMapper objectMapper, HttpClient httpClient) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public GitHubAuthService(
            String appId,
            String installationId,
            String privateKey,
            String apiUrl,
            ObjectMapper objectMapper,
            HttpClient httpClient) {
        this(objectMapper, httpClient);
        this.publishEnabled = true;
        this.appId = appId;
        this.installationId = installationId;
        this.privateKey = privateKey;
        this.apiUrl = apiUrl != null && !apiUrl.isBlank() ? apiUrl : "https://api.github.com";
    }

    public String getInstallationAccessToken() {
        return getInstallationToken();
    }

    public String getInstallationToken() {
        if (!publishEnabled) {
            throw new IllegalStateException("GitHub compliance publishing is disabled (app.github.publish.enabled=false)");
        }

        CachedToken current = this.cachedToken;
        if (current != null && current.isValid()) {
            return current.token();
        }

        synchronized (tokenLock) {
            current = this.cachedToken;
            if (current != null && current.isValid()) {
                return current.token();
            }
            CachedToken fresh = exchangeInstallationToken();
            this.cachedToken = fresh;
            return fresh.token();
        }
    }

    public void invalidateToken() {
        synchronized (tokenLock) {
            this.cachedToken = null;
        }
    }

    public String mintJwt() {
        if (appId == null || appId.isBlank()) {
            throw new IllegalStateException("app.github.app-id is not configured");
        }
        PrivateKey key = getOrParsePrivateKey();
        long now = Instant.now().getEpochSecond();
        long iat = now - 60; // 60s in the past for clock drift
        long exp = iat + 600; // 10 minutes maximum

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iat", iat);
        claims.put("exp", exp);
        claims.put("iss", appId);

        try {
            String payloadJson = objectMapper.writeValueAsString(claims);
            String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
            String signingInput = JWT_HEADER_B64 + "." + payloadB64;

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] signatureBytes = signature.sign();
            String signatureB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            return signingInput + "." + signatureB64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to mint RS256 JWT for GitHub App: " + e.getMessage(), e);
        }
    }

    private CachedToken exchangeInstallationToken() {
        String jwt = mintJwt();
        if (installationId == null || installationId.isBlank()) {
            throw new IllegalStateException("app.github.installation-id is required for publishing");
        }

        String baseUrl = apiUrl != null && !apiUrl.isBlank() ? apiUrl : "https://api.github.com";
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        String url = baseUrl + "/app/installations/" + installationId + "/access_tokens";
        log.debug("Exchanging GitHub App installation token at {}", url);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + jwt)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("User-Agent", "scim-validator-ui")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                String errorMsg = "HTTP " + response.statusCode();
                try {
                    JsonNode errNode = objectMapper.readTree(response.body());
                    if (errNode.has("message")) {
                        errorMsg += " - " + errNode.get("message").asText();
                    }
                } catch (Exception ignored) {
                    errorMsg += " - " + response.body();
                }
                throw new IllegalStateException("Failed to exchange GitHub App installation token: " + errorMsg);
            }

            JsonNode root = objectMapper.readTree(response.body());
            String token = root.path("token").asText(null);
            String expiresAtStr = root.path("expires_at").asText(null);

            if (token == null || token.isBlank()) {
                throw new IllegalStateException("GitHub installation token response missing 'token'");
            }
            Instant expiresAt = expiresAtStr != null ? Instant.parse(expiresAtStr) : Instant.now().plus(Duration.ofHours(1));
            log.info("Successfully acquired GitHub App installation token, expires at {}", expiresAt);
            return new CachedToken(token, expiresAt);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while exchanging GitHub App token", e);
        } catch (Exception e) {
            if (e instanceof IllegalStateException ise) throw ise;
            throw new IllegalStateException("Network error exchanging GitHub App token: " + e.getMessage(), e);
        }
    }

    private PrivateKey getOrParsePrivateKey() {
        if (cachedPrivateKey != null) {
            return cachedPrivateKey;
        }
        synchronized (tokenLock) {
            if (cachedPrivateKey != null) {
                return cachedPrivateKey;
            }
            if (privateKey == null || privateKey.isBlank()) {
                throw new IllegalStateException("app.github.private-key is not configured");
            }
            cachedPrivateKey = parsePemPrivateKey(privateKey);
            return cachedPrivateKey;
        }
    }

    public static PrivateKey parsePemPrivateKey(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("Private key PEM must not be null or blank");
        }
        String normalized = pem.trim();
        if ((normalized.startsWith("\"") && normalized.endsWith("\"")) ||
                (normalized.startsWith("'") && normalized.endsWith("'"))) {
            normalized = normalized.substring(1, normalized.length() - 1).trim();
        }
        normalized = normalized.replace("\\r\\n", "\n")
                .replace("\\n", "\n")
                .replace("\r\n", "\n");

        if (normalized.contains("ENCRYPTED")) {
            throw new IllegalArgumentException("Encrypted RSA private keys are not supported; provide an unencrypted PEM");
        }

        boolean isPkcs1 = normalized.contains("BEGIN RSA PRIVATE KEY");
        boolean isPkcs8 = normalized.contains("BEGIN PRIVATE KEY");

        String base64 = normalized
                .replaceAll("-----BEGIN [A-Z0-9 _-]+-----", "")
                .replaceAll("-----END [A-Z0-9 _-]+-----", "")
                .replaceAll("\\s+", "");

        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 payload in private key PEM: " + e.getMessage(), e);
        }

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            if (isPkcs1) {
                byte[] pkcs8Der = wrapPkcs1ToPkcs8(der);
                return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));
            } else if (isPkcs8) {
                return kf.generatePrivate(new PKCS8EncodedKeySpec(der));
            } else {
                try {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(der));
                } catch (InvalidKeySpecException e) {
                    byte[] pkcs8Der = wrapPkcs1ToPkcs8(der);
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));
                }
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException("Failed to decode RSA private key: " + e.getMessage(), e);
        }
    }

    public static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1Bytes) throws IOException {
        ByteArrayOutputStream octetStream = new ByteArrayOutputStream();
        octetStream.write(0x04); // OCTET STRING
        writeDerLength(octetStream, pkcs1Bytes.length);
        octetStream.write(pkcs1Bytes);

        ByteArrayOutputStream seqStream = new ByteArrayOutputStream();
        seqStream.write(new byte[]{0x02, 0x01, 0x00}); // INTEGER 0
        seqStream.write(RSA_ALGO_IDENTIFIER);
        seqStream.write(octetStream.toByteArray());
        byte[] seqBytes = seqStream.toByteArray();

        ByteArrayOutputStream pkcs8Stream = new ByteArrayOutputStream();
        pkcs8Stream.write(0x30); // SEQUENCE
        writeDerLength(pkcs8Stream, seqBytes.length);
        pkcs8Stream.write(seqBytes);

        return pkcs8Stream.toByteArray();
    }

    private static void writeDerLength(OutputStream out, int length) throws IOException {
        if (length < 128) {
            out.write(length);
        } else if (length <= 0xff) {
            out.write(0x81);
            out.write(length);
        } else if (length <= 0xffff) {
            out.write(0x82);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write(0x83);
            out.write((length >> 16) & 0xff);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
    }

    // Getters and setters for testing and configuration
    public boolean isPublishEnabled() {
        return publishEnabled;
    }

    public void setPublishEnabled(boolean publishEnabled) {
        this.publishEnabled = publishEnabled;
    }

    public String getAppId() {
        return appId;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public String getInstallationId() {
        return installationId;
    }

    public void setInstallationId(String installationId) {
        this.installationId = installationId;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
        synchronized (tokenLock) {
            this.cachedPrivateKey = null;
        }
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }
}
