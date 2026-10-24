package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Empirical challenger test suite for data sanitization zero-leak invariants,
 * submitter privacy guarantees, and SVG XML DOM geometry & gradient parsing.
 */
class SanitizationAndBadgeChallengerTest {

    private ComplianceBadgeGenerator badgeGenerator;
    private ObjectMapper objectMapper;
    private DocumentBuilder documentBuilder;

    @BeforeEach
    void setUp() throws Exception {
        badgeGenerator = new ComplianceBadgeGenerator();
        objectMapper = new ObjectMapper();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        documentBuilder = factory.newDocumentBuilder();
    }

    // =========================================================================
    // 1. Zero-Leak Sanitization Invariants
    // =========================================================================
    @Nested
    @DisplayName("Zero-Leak Sanitization Invariants")
    class ZeroLeakSanitizationTests {

        @Test
        @DisplayName("Should scrub adversarial URLs, credentials, tokens, IPs, and truncate long stack traces")
        void shouldScrubAdversarialErrorMessageInputs() {
            String targetUrl = "https://internal-vault.corp.local:8443/v2";

            // Test 1: Exact target URL in error message
            String err1 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Connection refused to https://internal-vault.corp.local:8443/v2/Users", targetUrl);
            assertThat(err1).doesNotContain("internal-vault.corp.local");
            assertThat(err1).contains("[TARGET_URL]");

            // Test 2: Bare target host
            String err2 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Host internal-vault.corp.local unreachable", targetUrl);
            assertThat(err2).doesNotContain("internal-vault.corp.local");
            assertThat(err2).contains("[TARGET_HOST]");

            // Test 3: Generic external or internal URL with credentials
            String err3 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Failure calling https://admin:superSecret123@10.0.0.1:8080/scim/v2/Users", null);
            assertThat(err3).doesNotContain("superSecret123");
            assertThat(err3).doesNotContain("https://admin:superSecret123@10.0.0.1:8080/scim/v2/Users");
            assertThat(err3).contains("[REDACTED_URL]");

            // Test 4: IPv4 address with port
            String err4 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Failed to connect to 192.168.1.100:8443 after timeout", null);
            assertThat(err4).doesNotContain("192.168.1.100");
            assertThat(err4).contains("[REDACTED_IP]");

            // Test 5: Authorization Bearer header
            String err5 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Failed with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secretSignature12345", null);
            assertThat(err5).doesNotContain("secretSignature12345");
            assertThat(err5).contains("Authorization: [REDACTED]");

            // Test 6: Bare Bearer token
            String err6 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Invalid token bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenBody12345678", null);
            assertThat(err6).doesNotContain("tokenBody12345678");
            assertThat(err6).contains("Bearer [REDACTED_TOKEN]");

            // Test 7: Basic Auth header and bare Basic auth
            String err7 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Header Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ= rejected", null);
            assertThat(err7).doesNotContain("dXNlcm5hbWU6cGFzc3dvcmQ=");
            assertThat(err7).contains("Authorization: [REDACTED]");

            String err8 = ComplianceReportGenerator.sanitizeErrorMessage(
                    "Credentials Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NQ== invalid", null);
            assertThat(err8).doesNotContain("dXNlcm5hbWU6cGFzc3dvcmQxMjM0NQ==");
            assertThat(err8).contains("Basic [REDACTED_AUTH]");

            // Test 8: Deep stack trace payload bounded to 300 chars
            String massiveStackTrace = "java.lang.RuntimeException: SCIM error\n" +
                    "    at de.palsoftware.scim.client.ScimClient.send(ScimClient.java:142)\n".repeat(20);
            String err9 = ComplianceReportGenerator.sanitizeErrorMessage(massiveStackTrace, null);
            assertThat(err9).isNotNull();
            assertThat(err9.length()).isLessThanOrEqualTo(300);
            assertThat(err9).endsWith("...");
        }

        @Test
        @DisplayName("Generated report JSON must contain zero target URLs or secrets and pass assertSanitized")
        void shouldProduceZeroLeakReportJson() throws Exception {
            String secretHost = "secret-scim-backend.corp.internal";
            String secretTargetUrl = "https://" + secretHost + ":8443/scim/v2";

            UUID runId = UUID.randomUUID();
            ValidationRun run = new ValidationRun();
            org.springframework.test.util.ReflectionTestUtils.setField(run, "id", runId);
            run.setName("Adversarial Invariant Run");
            run.setTargetUrl(secretTargetUrl);
            run.setStatus("FAILED");
            run.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC));

            ValidationRunPublication pub = new ValidationRunPublication();
            pub.setRunId(runId);
            pub.setProductName("Hardened SCIM Product");
            pub.setProductSlug("hardened-scim-product");
            pub.setProductVersion("3.0.0");
            pub.setVendorName("Acme Security Corp");
            pub.setProjectUrl("https://acme.org/scim");
            pub.setLicenseType("Apache-2.0");
            pub.setShowSubmitter(false);
            pub.setCreatedByEmail("auditor@corp.internal");
            pub.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));

            ValidationTestResult tr1 = new ValidationTestResult();
            tr1.setTestIdentifier("SEC_01");
            tr1.setDisplayName("SEC_01: Secure User Provisioning");
            tr1.setStatus("FAILED");
            tr1.setErrorMessage("HTTP 500 from " + secretTargetUrl + "/Users with Bearer eyJhbGciOiJIUzI1NiJ9.adversarialSecretToken");

            ValidationTestResult tr2 = new ValidationTestResult();
            tr2.setTestIdentifier("SEC_02");
            tr2.setDisplayName("SEC_02: IP Bound Endpoint");
            tr2.setStatus("FAILED");
            tr2.setErrorMessage("Failed to route to 10.240.0.5:9443: Authorization: Basic YWRtaW46c2VjcmV0");

            ComplianceScorecardView scorecard = new ComplianceScorecardView(
                    runId, "Run", secretTargetUrl, OffsetDateTime.now(ZoneOffset.UTC), "FAILED",
                    65, ColourGradient.ORANGE, true, null,
                    null, null, null,
                    Collections.emptyList(), 6, 6, 10,
                    157, 100, 57, 0,
                    Collections.emptyMap(), Collections.emptyList()
            );

            SanitizedComplianceReport report = ComplianceReportGenerator.buildSanitizedReport(
                    run, pub, scorecard, List.of(tr1, tr2)
            );

            String json = objectMapper.writeValueAsString(report);

            // Invariant 1: Target URL and host are never in JSON
            assertThat(json).doesNotContain(secretTargetUrl);
            assertThat(json).doesNotContain(secretHost);

            // Invariant 2: Bearer and Basic tokens are scrubbed
            assertThat(json).doesNotContain("eyJhbGciOiJIUzI1NiJ9.adversarialSecretToken");
            assertThat(json).doesNotContain("YWRtaW46c2VjcmV0");

            // Invariant 3: Raw IP address is scrubbed
            assertThat(json).doesNotContain("10.240.0.5");

            // Invariant 4: No raw HTTP exchange structures
            assertThat(json).doesNotContain("\"requestBody\"");
            assertThat(json).doesNotContain("\"responseBody\"");
            assertThat(json).doesNotContain("\"requestHeaders\"");
            assertThat(json).doesNotContain("\"responseHeaders\"");

            // Invariant 5: Programmatic assertion barrier passes cleanly
            assertThatCode(() -> ComplianceReportGenerator.assertSanitized(json, secretTargetUrl))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("assertSanitized must reject leaked targetUrl")
        void assertSanitizedShouldThrowOnLeakedTargetUrl() {
            String targetUrl = "https://sensitive-target.corp:8443/scim";
            String leak = "{\"url\":\"https://sensitive-target.corp:8443/scim\"}";
            assertThatThrownBy(() -> ComplianceReportGenerator.assertSanitized(leak, targetUrl))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("targetUrl detected");
        }

        @Test
        @DisplayName("assertSanitized must reject leaked target host (FINDING: caught and swallowed by try-catch)")
        void assertSanitizedShouldThrowOnLeakedTargetHost() {
            String targetUrl = "https://sensitive-target.corp:8443/scim";
            String leak = "{\"host\":\"sensitive-target.corp\"}";
            assertThatThrownBy(() -> ComplianceReportGenerator.assertSanitized(leak, targetUrl))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("target host");
        }

        @Test
        @DisplayName("assertSanitized must reject leaked Bearer token pattern")
        void assertSanitizedShouldThrowOnLeakedBearerToken() {
            String targetUrl = "https://sensitive-target.corp:8443/scim";
            String leak = "{\"token\":\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"}";
            assertThatThrownBy(() -> ComplianceReportGenerator.assertSanitized(leak, targetUrl))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("authorization token pattern");
        }

        @Test
        @DisplayName("assertSanitized must reject raw HTTP exchange payload fields")
        void assertSanitizedShouldThrowOnRawHttpExchangePayload() {
            String targetUrl = "https://sensitive-target.corp:8443/scim";
            String leak = "{\"requestBody\":\"{\\\"name\\\":\\\"alice\\\"}\"}";
            assertThatThrownBy(() -> ComplianceReportGenerator.assertSanitized(leak, targetUrl))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("raw HTTP exchange payload");
        }

        @Test
        @DisplayName("Query parameters on targetUrl must not leak secrets into sanitized error message")
        void queryParametersOnTargetUrlMustNotLeakSecrets() {
            String targetUrl = "https://sensitive.corp";
            String rawError = "Error connecting to https://sensitive.corp/scim/v2/Users?apiKey=secret-api-key-12345";
            String sanitized = ComplianceReportGenerator.sanitizeErrorMessage(rawError, targetUrl);
            assertThat(sanitized).doesNotContain("secret-api-key-12345");
        }

        @Test
        @DisplayName("Private key fragments in error messages must not leak into report")
        void privateKeyFragmentsMustNotLeak() {
            String rawError = "Crypto error using key: -----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----";
            String sanitized = ComplianceReportGenerator.sanitizeErrorMessage(rawError, null);
            assertThat(sanitized).doesNotContain("BEGIN PRIVATE KEY");
        }

        @Test
        @DisplayName("Should scrub case-variant target hosts/URLs and IPv6 addresses and fail assertSanitized on leaks")
        void shouldScrubCaseVariantHostsAndIpv6Literals() {
            String targetUrl = "https://SCIM.Internal.Corp:8443/scim/v2";
            String rawError = "Connection failed to https://scim.internal.corp:8443/scim/v2/Users on host scim.internal.corp and [2001:db8::1] or [::1]";
            String sanitized = ComplianceReportGenerator.sanitizeErrorMessage(rawError, targetUrl);
            assertThat(sanitized).doesNotContainIgnoringCase("scim.internal.corp");
            assertThat(sanitized).doesNotContain("2001:db8::1");
            assertThat(sanitized).doesNotContain("[::1]");

            // assertSanitized rejects case-differing host leaks and IPv6 literals
            assertThatThrownBy(() ->
                    ComplianceReportGenerator.assertSanitized(
                            "{\"metadata\":{\"productName\":\"Leak scim.internal.corp\"}}",
                            "https://SCIM.INTERNAL.CORP/v2"
                    )
            ).isInstanceOf(SecurityException.class);

            assertThatThrownBy(() ->
                    ComplianceReportGenerator.assertSanitized(
                            "{\"metadata\":{\"productName\":\"IPv6 [2001:db8::1] leak\"}}",
                            "https://example.com/v2"
                    )
            ).isInstanceOf(SecurityException.class);
        }
    }

    // =========================================================================
    // 2. Submitter Attribution Privacy Invariants
    // =========================================================================
    @Nested
    @DisplayName("Submitter Attribution Privacy Invariants")
    class SubmitterPrivacyTests {

        @Test
        @DisplayName("When showSubmitter is false, submitter email must be null and omitted from JSON")
        void shouldNullifySubmitterWhenShowSubmitterIsFalse() throws Exception {
            UUID runId = UUID.randomUUID();
            CompliancePublishRequest request = new CompliancePublishRequest(
                    runId, "Privacy SCIM", "privacy-scim", "1.0.0",
                    "Privacy Org", "https://privacy.org", "Apache-2.0",
                    false, // showSubmitter = false
                    90, "TEAL_GREEN", 9, 10,
                    "confidential-submitter@privacy.org"
            );

            ComplianceReportGenerator generator = new ComplianceReportGenerator();
            SanitizedComplianceReport report = generator.generate(request, OffsetDateTime.now(ZoneOffset.UTC));

            // Java record model verification
            assertThat(report.metadata().submitter()).isNull();

            // Serialized JSON verification (NON_NULL must omit "submitter")
            String json = objectMapper.writeValueAsString(report);
            assertThat(json).doesNotContain("confidential-submitter@privacy.org");
            assertThat(json).doesNotContain("\"submitter\"");
        }

        @Test
        @DisplayName("When showSubmitter is true, submitter email must be included in metadata and JSON")
        void shouldIncludeSubmitterWhenShowSubmitterIsTrue() throws Exception {
            UUID runId = UUID.randomUUID();
            CompliancePublishRequest request = new CompliancePublishRequest(
                    runId, "Public SCIM", "public-scim", "1.0.0",
                    "Public Org", "https://public.org", "MIT",
                    true, // showSubmitter = true
                    95, "EMERALD", 10, 10,
                    "public-author@public.org"
            );

            ComplianceReportGenerator generator = new ComplianceReportGenerator();
            SanitizedComplianceReport report = generator.generate(request, OffsetDateTime.now(ZoneOffset.UTC));

            assertThat(report.metadata().submitter()).isEqualTo("public-author@public.org");

            String json = objectMapper.writeValueAsString(report);
            assertThat(json).contains("\"submitter\":\"public-author@public.org\"");
        }

        @Test
        @DisplayName("buildSanitizedReport adheres to ValidationRunPublication.showSubmitter flag")
        void shouldAdhereToPublicationShowSubmitterFlag() {
            ValidationRun run = new ValidationRun();
            org.springframework.test.util.ReflectionTestUtils.setField(run, "id", UUID.randomUUID());
            run.setTargetUrl("https://scim.example.com");

            ComplianceScorecardView scorecard = new ComplianceScorecardView(
                    run.getId(), "Run", "https://scim.example.com", OffsetDateTime.now(ZoneOffset.UTC),
                    "PASSED", 88, ColourGradient.TEAL_GREEN, true, null,
                    null, null, null, Collections.emptyList(), 9, 9, 10,
                    157, 130, 27, 0, Collections.emptyMap(), Collections.emptyList()
            );

            // Case 1: showSubmitter = false
            ValidationRunPublication pubFalse = new ValidationRunPublication();
            pubFalse.setShowSubmitter(false);
            pubFalse.setCreatedByEmail("secret@internal.corp");
            SanitizedComplianceReport report1 = ComplianceReportGenerator.buildSanitizedReport(run, pubFalse, scorecard, Collections.emptyList());
            assertThat(report1.metadata().submitter()).isNull();

            // Case 2: showSubmitter = true
            ValidationRunPublication pubTrue = new ValidationRunPublication();
            pubTrue.setShowSubmitter(true);
            pubTrue.setCreatedByEmail("public@corp.org");
            SanitizedComplianceReport report2 = ComplianceReportGenerator.buildSanitizedReport(run, pubTrue, scorecard, Collections.emptyList());
            assertThat(report2.metadata().submitter()).isEqualTo("public@corp.org");
        }
    }

    // =========================================================================
    // 3. SVG XML DOM Geometry & Gradient Parsing across all 5 Brackets
    // =========================================================================
    @Nested
    @DisplayName("SVG XML DOM Geometry & Gradient Invariants")
    class SvgXmlDomInvariantsTests {

        @ParameterizedTest(name = "Bracket {0}: score={1}%, caps={2}/{3}, expectedGradient={4}")
        @CsvSource({
                "RED (0%),        0,   0, 10, RED",
                "RED (25%),      25,   2, 10, RED",
                "RED (49%),      49,   4, 10, RED",
                "ORANGE (50%),   50,   5, 10, ORANGE",
                "ORANGE (69%),   69,   6, 10, ORANGE",
                "AMBER (70%),    70,   7, 10, AMBER",
                "AMBER (75%),    75,   7, 10, AMBER",
                "AMBER (84%),    84,   8, 10, AMBER",
                "TEAL_GREEN (85%), 85, 8, 10, TEAL_GREEN",
                "TEAL_GREEN (94%), 94, 9, 10, TEAL_GREEN",
                "EMERALD (95%),  95,   9, 10, EMERALD",
                "EMERALD (100%), 100, 10, 10, EMERALD"
        })
        @DisplayName("SVG badges across all 5 brackets must parse as valid XML DOM with exact gradient stops and geometry")
        void shouldParseSvgXmlDomAcrossAllGradientBrackets(
                String label, int score, int compliantCaps, int totalCaps, String gradientName) throws Exception {

            ColourGradient expectedGradient = ColourGradient.valueOf(gradientName);
            String badgeId = "bracket-" + score;
            String svg = badgeGenerator.generate(score, compliantCaps, totalCaps, badgeId);

            assertThat(svg).isNotBlank();

            // 1. Parse with standard XML DocumentBuilder DOM parser (verifies well-formed XML)
            Document doc = documentBuilder.parse(new ByteArrayInputStream(svg.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();

            // 2. Verify root <svg> geometry and namespaces
            assertThat(root.getTagName()).isEqualTo("svg");
            assertThat(root.getAttribute("xmlns")).isEqualTo("http://www.w3.org/2000/svg");
            assertThat(root.getAttribute("xmlns:xlink")).isEqualTo("http://www.w3.org/1999/xlink");
            assertThat(root.getAttribute("height")).isEqualTo("20");

            int width = Integer.parseInt(root.getAttribute("width"));
            assertThat(width).isGreaterThanOrEqualTo(152); // leftWidth(60) + rightWidth(>=92)
            assertThat(root.getAttribute("viewBox")).isEqualTo("0 0 " + width + " 20");
            assertThat(root.getAttribute("role")).isEqualTo("img");

            String expectedValueText = score + "% · " + compliantCaps + "/" + totalCaps + " caps";
            assertThat(root.getAttribute("aria-label")).isEqualTo("SCIM 2.0: " + expectedValueText);

            // 3. Accessibility elements (<title> and <desc>)
            NodeList titleList = root.getElementsByTagName("title");
            assertThat(titleList.getLength()).isEqualTo(1);
            assertThat(titleList.item(0).getTextContent()).isEqualTo("SCIM 2.0: " + expectedValueText);

            NodeList descList = root.getElementsByTagName("desc");
            assertThat(descList.getLength()).isEqualTo(1);
            assertThat(descList.item(0).getTextContent())
                    .contains("SCIM 2.0 compliance scorecard: " + score + "% Core Conformance");

            // 4. Defs: LinearGradients and ClipPath
            String expectedGradId = "scim-g-" + badgeId;
            String expectedOverlayId = "scim-o-" + badgeId;
            String expectedClipId = "scim-c-" + badgeId;

            NodeList linearGradients = root.getElementsByTagName("linearGradient");
            assertThat(linearGradients.getLength()).isEqualTo(2);

            // Verify main score gradient
            Element mainGrad = findElementById(linearGradients, expectedGradId);
            assertThat(mainGrad).isNotNull();
            assertThat(mainGrad.getAttribute("x1")).isEqualTo("0%");
            assertThat(mainGrad.getAttribute("y1")).isEqualTo("0%");
            assertThat(mainGrad.getAttribute("x2")).isEqualTo("100%");
            assertThat(mainGrad.getAttribute("y2")).isEqualTo("100%");

            NodeList stops = mainGrad.getElementsByTagName("stop");
            assertThat(stops.getLength()).isEqualTo(2);
            Element stop0 = (Element) stops.item(0);
            Element stop1 = (Element) stops.item(1);
            assertThat(stop0.getAttribute("offset")).isEqualTo("0%");
            assertThat(stop0.getAttribute("stop-color")).isEqualTo(expectedGradient.getStartColor());
            assertThat(stop1.getAttribute("offset")).isEqualTo("100%");
            assertThat(stop1.getAttribute("stop-color")).isEqualTo(expectedGradient.getEndColor());

            // Verify overlay gloss gradient
            Element overlayGrad = findElementById(linearGradients, expectedOverlayId);
            assertThat(overlayGrad).isNotNull();

            // Verify clipPath
            NodeList clipPaths = root.getElementsByTagName("clipPath");
            assertThat(clipPaths.getLength()).isEqualTo(1);
            Element clipPath = (Element) clipPaths.item(0);
            assertThat(clipPath.getAttribute("id")).isEqualTo(expectedClipId);
            Element clipRect = (Element) clipPath.getElementsByTagName("rect").item(0);
            assertThat(clipRect.getAttribute("width")).isEqualTo(String.valueOf(width));
            assertThat(clipRect.getAttribute("height")).isEqualTo("20");
            assertThat(clipRect.getAttribute("rx")).isEqualTo("3");

            // 5. Geometry containers (<g clip-path="...">)
            NodeList rects = root.getElementsByTagName("rect");
            // 1 in clipPath + 3 in clipped group = 4 rects
            assertThat(rects.getLength()).isEqualTo(4);

            // Verify gradient fill reference
            Element gradientRect = (Element) rects.item(2);
            assertThat(gradientRect.getAttribute("fill")).isEqualTo("url(#" + expectedGradId + ")");
            assertThat(Integer.parseInt(gradientRect.getAttribute("x"))).isEqualTo(60);
            assertThat(Integer.parseInt(gradientRect.getAttribute("width"))).isGreaterThanOrEqualTo(92);

            // 6. Text Elements & Anchors
            NodeList textGroups = root.getElementsByTagName("g");
            Element textGroup = (Element) textGroups.item(1);
            assertThat(textGroup.getAttribute("text-anchor")).isEqualTo("middle");
            assertThat(textGroup.getAttribute("aria-hidden")).isEqualTo("true");

            NodeList textNodes = textGroup.getElementsByTagName("text");
            assertThat(textNodes.getLength()).isEqualTo(4);
            assertThat(textNodes.item(0).getTextContent()).isEqualTo("SCIM 2.0");
            assertThat(textNodes.item(1).getTextContent()).isEqualTo("SCIM 2.0");
            assertThat(textNodes.item(2).getTextContent()).isEqualTo(expectedValueText);
            assertThat(textNodes.item(3).getTextContent()).isEqualTo(expectedValueText);
        }

        @Test
        @DisplayName("SVG badge ID sanitization prevents XML attribute injection")
        void shouldSanitizeBadgeIdToPreventXmlInjection() throws Exception {
            String maliciousId = "\"><script>alert(1)</script><linearGradient id=\"injected";
            String svg = badgeGenerator.generate(95, 10, 10, maliciousId);

            // Must parse cleanly without throwing XML parse exception
            Document doc = documentBuilder.parse(new ByteArrayInputStream(svg.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();

            // Malicious script tags must not exist
            assertThat(root.getElementsByTagName("script").getLength()).isEqualTo(0);

            // ID should only retain alphanumeric characters
            String sanitizedSafeId = "scriptalert1scriptlinearGradientidinjected";
            assertThat(root.getElementsByTagName("linearGradient").item(0).getAttributes().getNamedItem("id").getTextContent())
                    .isEqualTo("scim-g-" + sanitizedSafeId);
        }

        @ParameterizedTest(name = "Fallback test for ID: ''{0}''")
        @ValueSource(strings = {"", "   ", "???", "$$$", "><", "   !@#   "})
        @DisplayName("SVG badge ID fallback to 'def' when badgeId is empty, blank, or stripped")
        void shouldFallbackToDefWhenBadgeIdIsBlankOrStripped(String blankOrStrippedId) throws Exception {
            String svg = badgeGenerator.generate(95, 10, 10, blankOrStrippedId);
            Document doc = documentBuilder.parse(new ByteArrayInputStream(svg.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();
            int width = Integer.parseInt(root.getAttribute("width"));
            assertThat(root.getAttribute("viewBox")).isEqualTo("0 0 " + width + " 20");
            assertThat(root.getElementsByTagName("linearGradient").item(0).getAttributes().getNamedItem("id").getTextContent())
                    .isEqualTo("scim-g-def");
            assertThat(root.getElementsByTagName("clipPath").item(0).getAttributes().getNamedItem("id").getTextContent())
                    .isEqualTo("scim-c-def");
        }

        @Test
        @DisplayName("SVG badge ID fallback to 'def' when badgeId is null")
        void shouldFallbackToDefWhenBadgeIdIsNull() throws Exception {
            String svg = badgeGenerator.generate(95, 10, 10, null);
            Document doc = documentBuilder.parse(new ByteArrayInputStream(svg.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();
            int width = Integer.parseInt(root.getAttribute("width"));
            assertThat(root.getAttribute("viewBox")).isEqualTo("0 0 " + width + " 20");
            assertThat(root.getElementsByTagName("linearGradient").item(0).getAttributes().getNamedItem("id").getTextContent())
                    .isEqualTo("scim-g-def");
        }

        private Element findElementById(NodeList list, String id) {
            for (int i = 0; i < list.getLength(); i++) {
                Element el = (Element) list.item(i);
                if (id.equals(el.getAttribute("id"))) {
                    return el;
                }
            }
            return null;
        }
    }
}
