package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import de.palsoftware.scim.validator.ui.model.spec.SanitizedComplianceReport.*;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

@Service
public class ComplianceReportGenerator {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s\"'>\\]\\)]+");
    private static final Pattern BEARER_PATTERN = Pattern.compile("(?i)bearer\\s+[A-Za-z0-9_\\-\\.~+/=]{8,}");
    private static final Pattern BASIC_PATTERN = Pattern.compile("(?i)basic\\s+[A-Za-z0-9+/=]{8,}");
    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile("(?i)authorization:\\s*[^;\\r\\n]+");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?\\b");
    private static final Pattern TARGET_URL_RESIDUAL_PATTERN = Pattern.compile("\\[TARGET_URL\\][^\\s\"'>\\]\\)]*");
    private static final Pattern TARGET_HOST_RESIDUAL_PATTERN = Pattern.compile("\\[TARGET_HOST\\][^\\s\"'>\\]\\)]*");
    private static final Pattern PEM_PRIVATE_KEY_BLOCK_PATTERN = Pattern.compile("(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----");
    private static final Pattern PEM_PRIVATE_KEY_HEADER_PATTERN = Pattern.compile("-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----");
    private static final Pattern SENSITIVE_QUERY_PARAM_PATTERN = Pattern.compile("(?i)(?<=[?&])(?:api[_-]?key|token|secret|password|auth|client_secret|access_token)=[^\\s\"'>\\]\\)&]+");
    public static final String DEFAULT_SAMPLE_RUN_IDS = "11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222";

    @Value("${app.compliance.sample-run-ids:" + DEFAULT_SAMPLE_RUN_IDS + "}")
    private String sampleRunIdsConfig = DEFAULT_SAMPLE_RUN_IDS;

    private final ValidationRunRepository runRepository;
    private final ValidationTestResultRepository testResultRepository;
    private final ComplianceScoreService scoreService;
    private final ValidationHttpExchangeRepository exchangeRepository;

    public ComplianceReportGenerator() {
        this(null, null, null, null);
    }

    public ComplianceReportGenerator(
            ValidationRunRepository runRepository,
            ValidationTestResultRepository testResultRepository,
            ComplianceScoreService scoreService) {
        this(runRepository, testResultRepository, scoreService, null);
    }

    @Autowired
    public ComplianceReportGenerator(
            @Autowired(required = false) ValidationRunRepository runRepository,
            @Autowired(required = false) ValidationTestResultRepository testResultRepository,
            @Autowired(required = false) ComplianceScoreService scoreService,
            @Autowired(required = false) ValidationHttpExchangeRepository exchangeRepository) {
        this.runRepository = runRepository;
        this.testResultRepository = testResultRepository;
        this.scoreService = scoreService;
        this.exchangeRepository = exchangeRepository;
    }

    public String getTargetUrl(java.util.UUID runId) {
        if (runRepository != null && runId != null) {
            return runRepository.findById(runId).map(ValidationRun::getTargetUrl).orElse(null);
        }
        return null;
    }

    /**
     * Builds a sanitized report from a publish request and publication timestamp.
     */
    public SanitizedComplianceReport generate(CompliancePublishRequest request, OffsetDateTime publishedAt) {
        Objects.requireNonNull(request, "request must not be null");

        ValidationRun run = null;
        List<ValidationTestResult> testResults = null;
        ComplianceScorecardView scorecard = request.scorecard();

        if (runRepository != null && request.runId() != null) {
            run = runRepository.findById(request.runId()).orElse(null);
        }
        if (testResultRepository != null && request.runId() != null) {
            testResults = testResultRepository.findByRunIdOrderByStartedAtAsc(request.runId());
        }
        if (scorecard == null && run != null && scoreService != null) {
            try {
                List<ValidationHttpExchange> exchanges = (exchangeRepository != null && request.runId() != null)
                        ? exchangeRepository.findServiceProviderConfigExchangesByRunId(request.runId())
                        : Collections.emptyList();
                scorecard = scoreService.computeScorecard(
                        run,
                        testResults,
                        exchanges != null ? exchanges : Collections.emptyList());
            } catch (Exception ignored) {
            }
        }

        return buildReportFromComponents(
                request,
                run,
                scorecard,
                testResults,
                publishedAt
        );
    }

    /**
     * Builds a sanitized report from existing validation run models using the configured
     * {@code app.compliance.sample-run-ids} list.
     */
    public SanitizedComplianceReport generate(
            ValidationRun run,
            ValidationRunPublication publication,
            ComplianceScorecardView scorecard,
            List<ValidationTestResult> testResults) {
        return buildSanitizedReport(run, publication, scorecard, testResults, sampleRunIdsConfig);
    }

    /**
     * Static convenience builder using {@link #DEFAULT_SAMPLE_RUN_IDS}.
     * Prefer the instance {@link #generate(ValidationRun, ValidationRunPublication, ComplianceScorecardView, List)}
     * method or {@link #buildSanitizedReport(ValidationRun, ValidationRunPublication, ComplianceScorecardView, List, String)}
     * when custom {@code app.compliance.sample-run-ids} configuration should be applied.
     */
    public static SanitizedComplianceReport buildSanitizedReport(
            ValidationRun run,
            ValidationRunPublication publication,
            ComplianceScorecardView scorecard,
            List<ValidationTestResult> testResults) {
        return buildSanitizedReport(run, publication, scorecard, testResults, DEFAULT_SAMPLE_RUN_IDS);
    }

    public static SanitizedComplianceReport buildSanitizedReport(
            ValidationRun run,
            ValidationRunPublication publication,
            ComplianceScorecardView scorecard,
            List<ValidationTestResult> testResults,
            String sampleIdsCsv) {

        Objects.requireNonNull(run, "run must not be null");
        Objects.requireNonNull(scorecard, "scorecard must not be null");

        String targetUrl = run.getTargetUrl();
        String publishedAtIso = null;
        String submitter = null;
        String productName = "SCIM Server";
        String productSlug = "scim-server";
        String productVersion = "1.0.0";
        String vendorName = null;
        String projectUrl = null;
        String licenseType = "Proprietary";

        if (publication != null) {
            publishedAtIso = publication.getPublishedAt() != null
                    ? publication.getPublishedAt().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    : null;
            submitter = publication.isShowSubmitter() ? publication.getCreatedByEmail() : null;
            if (publication.getProductName() != null) productName = publication.getProductName();
            if (publication.getProductSlug() != null) productSlug = publication.getProductSlug();
            if (publication.getProductVersion() != null) productVersion = publication.getProductVersion();
            vendorName = publication.getVendorName();
            projectUrl = publication.getProjectUrl();
            if (publication.getLicenseType() != null) licenseType = publication.getLicenseType();
        }

        if (publishedAtIso == null && scorecard.executedAt() != null) {
            publishedAtIso = scorecard.executedAt().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        }

        ReportMetadata metadata = new ReportMetadata(
                run.getId() != null ? run.getId().toString() : null,
                productName,
                productSlug,
                productVersion,
                vendorName,
                projectUrl,
                licenseType,
                publishedAtIso,
                submitter,
                isConfiguredSampleRun(run.getId(), sampleIdsCsv) ? Boolean.TRUE : null
        );

        NormativeLevelBreakdown normative = new NormativeLevelBreakdown(
                scorecard.mustBreakdown(),
                scorecard.shouldBreakdown(),
                scorecard.mayBreakdown()
        );

        CapabilitySummary capSummary = new CapabilitySummary(
                scorecard.supportedCapabilitiesCount(),
                scorecard.compliantCapabilitiesCount(),
                scorecard.totalCapabilitiesCount()
        );

        RequirementCounts reqCounts = new RequirementCounts(
                scorecard.catalogRequirementsTotal(),
                scorecard.activeRequirementsCount(),
                scorecard.excludedRequirementsCount(),
                scorecard.untestedRequirementsCount()
        );

        ReportScorecard scorecardDto = new ReportScorecard(
                scorecard.coreScore(),
                ColourGradientInfo.from(scorecard.colourGradient()),
                scorecard.publishEligible(),
                normative,
                scorecard.capabilities(),
                capSummary,
                reqCounts,
                scorecard.rfcSummaries(),
                scorecard.requirementMatrix()
        );

        List<SanitizedTestResult> sanitizedTests = sanitizeTestResults(testResults, targetUrl);

        return new SanitizedComplianceReport(
                SanitizedComplianceReport.SCHEMA_URL,
                SanitizedComplianceReport.CURRENT_SCHEMA_VERSION,
                metadata,
                scorecardDto,
                sanitizedTests
        );
    }

    private SanitizedComplianceReport buildReportFromComponents(
            CompliancePublishRequest request,
            ValidationRun run,
            ComplianceScorecardView scorecard,
            List<ValidationTestResult> testResults,
            OffsetDateTime publishedAt) {

        String targetUrl = (request.targetUrl() != null && !request.targetUrl().isBlank())
                ? request.targetUrl()
                : (run != null ? run.getTargetUrl() : null);
        String publishedAtIso = publishedAt != null
                ? publishedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                : OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        String submitter = request.showSubmitter() ? request.actorEmail() : null;

        boolean isSample = Boolean.TRUE.equals(request.isSampleFixture())
                || isConfiguredSampleRun(request.runId(), sampleRunIdsConfig);
        ReportMetadata metadata = new ReportMetadata(
                request.runId() != null ? request.runId().toString() : null,
                request.productName(),
                request.productSlug(),
                request.productVersion(),
                request.vendorName(),
                request.projectUrl(),
                request.licenseType(),
                publishedAtIso,
                submitter,
                isSample ? Boolean.TRUE : null
        );

        ReportScorecard scorecardDto;
        if (scorecard != null) {
            NormativeLevelBreakdown normative = new NormativeLevelBreakdown(
                    scorecard.mustBreakdown(),
                    scorecard.shouldBreakdown(),
                    scorecard.mayBreakdown()
            );

            CapabilitySummary capSummary = new CapabilitySummary(
                    scorecard.supportedCapabilitiesCount(),
                    scorecard.compliantCapabilitiesCount(),
                    scorecard.totalCapabilitiesCount()
            );

            RequirementCounts reqCounts = new RequirementCounts(
                    scorecard.catalogRequirementsTotal(),
                    scorecard.activeRequirementsCount(),
                    scorecard.excludedRequirementsCount(),
                    scorecard.untestedRequirementsCount()
            );

            scorecardDto = new ReportScorecard(
                    scorecard.coreScore(),
                    ColourGradientInfo.from(scorecard.colourGradient()),
                    scorecard.publishEligible(),
                    normative,
                    scorecard.capabilities(),
                    capSummary,
                    reqCounts,
                    scorecard.rfcSummaries(),
                    scorecard.requirementMatrix()
            );
        } else {
            int minScore = scoreService != null ? scoreService.getMinPublishScore() : ComplianceScoreService.DEFAULT_MIN_PUBLISH_SCORE;
            ColourGradientInfo gradInfo = ColourGradientInfo.from(request.colourGradient(), request.coreScore());
            scorecardDto = new ReportScorecard(
                    request.coreScore(),
                    gradInfo,
                    request.coreScore() >= minScore,
                    null,
                    Collections.emptyList(),
                    new CapabilitySummary(request.supportedCapabilities(), request.supportedCapabilities(), request.totalCapabilities()),
                    null,
                    Collections.emptyMap(),
                    Collections.emptyList()
            );
        }

        List<SanitizedTestResult> sanitizedTests = sanitizeTestResults(testResults, targetUrl);

        return new SanitizedComplianceReport(
                SanitizedComplianceReport.SCHEMA_URL,
                SanitizedComplianceReport.CURRENT_SCHEMA_VERSION,
                metadata,
                scorecardDto,
                sanitizedTests
        );
    }

    private static List<SanitizedTestResult> sanitizeTestResults(List<ValidationTestResult> testResults, String targetUrl) {
        List<SanitizedTestResult> sanitizedTests = new ArrayList<>();
        if (testResults != null) {
            for (ValidationTestResult tr : testResults) {
                long duration = (tr.getStartedAt() != null && tr.getFinishedAt() != null)
                        ? Duration.between(tr.getStartedAt(), tr.getFinishedAt()).toMillis()
                        : 0L;

                String sanitizedError = sanitizeErrorMessage(tr.getErrorMessage(), targetUrl);

                String testId = ComplianceScoreService.extractTestId(tr);
                sanitizedTests.add(new SanitizedTestResult(
                        testId != null ? testId : tr.getTestName(),
                        tr.getDisplayName(),
                        tr.getClassName(),
                        tr.getTestName(),
                        tr.getStatus(),
                        duration,
                        sanitizedError
                ));
            }
        }
        return sanitizedTests;
    }

    public static String sanitizeErrorMessage(String rawError, String targetUrl) {
        if (rawError == null || rawError.isBlank()) {
            return null;
        }

        String sanitized = rawError;

        // Strip target URL explicitly
        if (targetUrl != null && !targetUrl.isBlank()) {
            sanitized = sanitized.replace(targetUrl, "[TARGET_URL]");
            try {
                URI uri = URI.create(targetUrl);
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    sanitized = sanitized.replace(uri.getHost(), "[TARGET_HOST]");
                }
            } catch (Exception ignored) {
            }
            // Scrub residual path and query parameters attached to target URL/host tokens
            sanitized = TARGET_URL_RESIDUAL_PATTERN.matcher(sanitized).replaceAll("[TARGET_URL]");
            sanitized = TARGET_HOST_RESIDUAL_PATTERN.matcher(sanitized).replaceAll("[TARGET_HOST]");
        }

        // Scrub general URLs
        sanitized = URL_PATTERN.matcher(sanitized).replaceAll("[REDACTED_URL]");
        // Scrub PEM private key blocks and headers
        sanitized = PEM_PRIVATE_KEY_BLOCK_PATTERN.matcher(sanitized).replaceAll("[REDACTED_PRIVATE_KEY]");
        sanitized = PEM_PRIVATE_KEY_HEADER_PATTERN.matcher(sanitized).replaceAll("[REDACTED_PRIVATE_KEY]");
        // Scrub Authorization and Bearer tokens
        sanitized = AUTH_HEADER_PATTERN.matcher(sanitized).replaceAll("Authorization: [REDACTED]");
        sanitized = BEARER_PATTERN.matcher(sanitized).replaceAll("Bearer [REDACTED_TOKEN]");
        sanitized = BASIC_PATTERN.matcher(sanitized).replaceAll("Basic [REDACTED_AUTH]");
        // Scrub IP addresses
        sanitized = IPV4_PATTERN.matcher(sanitized).replaceAll("[REDACTED_IP]");
        // Scrub sensitive query parameters
        sanitized = SENSITIVE_QUERY_PARAM_PATTERN.matcher(sanitized).replaceAll("[REDACTED_PARAM]");

        // Prevent stack trace or huge payloads
        if (sanitized.length() > 300) {
            sanitized = sanitized.substring(0, 297) + "...";
        }

        return sanitized;
    }

    /**
     * Programmatic security assertion ensuring ZERO target URLs or credentials leaked.
     * Always forbids the full targetUrl everywhere (including metadata), and uses Jackson
     * tree inspection to exempt only metadata.projectUrl and metadata.submitter from the
     * host-only check when projectUrl is a distinct public URL.
     */
    public static void assertSanitized(String json, String targetUrl) {
        if (json == null) {
            return;
        }

        if (targetUrl != null && !targetUrl.isBlank()) {
            if (json.contains(targetUrl)) {
                throw new SecurityException("Sanitization violation: targetUrl detected in report JSON!");
            }
            String host = null;
            try {
                URI uri = URI.create(targetUrl);
                host = uri.getHost();
            } catch (Exception ignored) {
            }
            if (host != null && !host.isBlank()) {
                String hostCheckJson = stripPublicProjectAndSubmitterFromMetadata(json);
                if (hostCheckJson.contains(host)) {
                    throw new SecurityException("Sanitization violation: target host (" + host + ") detected in report JSON!");
                }
            }
        }

        if (Pattern.compile("(?i)authorization:\\s*bearer|bearer\\s+[a-z0-9_\\-\\.~+/=]{20,}").matcher(json).find()) {
            throw new SecurityException("Sanitization violation: authorization token pattern detected in report JSON!");
        }

        if (Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----").matcher(json).find()) {
            throw new SecurityException("Sanitization violation: private key pattern detected in report JSON!");
        }

        if (json.contains("\"requestBody\"") || json.contains("\"responseBody\"") ||
                json.contains("\"requestHeaders\"") || json.contains("\"responseHeaders\"")) {
            throw new SecurityException("Sanitization violation: raw HTTP exchange payload detected in report JSON!");
        }
    }

    public void setSampleRunIdsConfig(String sampleRunIdsConfig) {
        this.sampleRunIdsConfig = sampleRunIdsConfig;
    }

    public static boolean isSampleRun(java.util.UUID runId) {
        return isConfiguredSampleRun(runId, DEFAULT_SAMPLE_RUN_IDS);
    }

    public static boolean isConfiguredSampleRun(java.util.UUID runId, String sampleIdsCsv) {
        if (runId == null || sampleIdsCsv == null || sampleIdsCsv.isBlank()) {
            return false;
        }
        String target = runId.toString();
        for (String token : sampleIdsCsv.split(",")) {
            if (target.equalsIgnoreCase(token.trim())) {
                return true;
            }
        }
        return false;
    }

    private static String stripPublicProjectAndSubmitterFromMetadata(String json) {
        try {
            JsonNode root = OBJECT_MAPPER.readTree(json);
            if (root != null && root.isObject()) {
                ObjectNode rootObj = (ObjectNode) root;
                JsonNode metaNode = rootObj.get("metadata");
                if (metaNode != null && metaNode.isObject()) {
                    ObjectNode metaObj = (ObjectNode) metaNode;
                    metaObj.remove("projectUrl");
                    metaObj.remove("submitter");
                    return OBJECT_MAPPER.writeValueAsString(rootObj);
                }
            }
        } catch (Exception ignored) {
            // Fall back to checking raw json if not a JSON object
        }
        return json;
    }
}
