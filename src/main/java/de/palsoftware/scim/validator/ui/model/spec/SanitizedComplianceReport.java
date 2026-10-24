package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SanitizedComplianceReport(
        @JsonProperty("$schema") String schema,
        @JsonProperty("schemaVersion") String schemaVersion,
        @JsonProperty("metadata") ReportMetadata metadata,
        @JsonProperty("scorecard") ReportScorecard scorecard,
        @JsonProperty("testResults") List<SanitizedTestResult> testResults
) {
    public static final String CURRENT_SCHEMA_VERSION = "1.0.0";
    public static final String SCHEMA_URL = "https://scimsandbox.net/schemas/compliance-report-v1.json";

    public SanitizedComplianceReport {
        if (schema == null) {
            schema = SCHEMA_URL;
        }
        if (schemaVersion == null) {
            schemaVersion = CURRENT_SCHEMA_VERSION;
        }
        if (testResults == null) {
            testResults = Collections.emptyList();
        } else {
            testResults = Collections.unmodifiableList(testResults);
        }
    }

    public SanitizedComplianceReport(
            String product,
            String version,
            String vendor,
            String projectUrl,
            String license,
            String publishedAt,
            String runId,
            int coreScore,
            ColourGradientInfo colourGradient,
            NormativeLevelBreakdown normativeBreakdown,
            List<CapabilityStatus> capabilityBreakdown,
            List<RequirementTraceResult> traceabilityMatrix,
            List<SanitizedTestResult> testResults) {
        this(
                SCHEMA_URL,
                CURRENT_SCHEMA_VERSION,
                new ReportMetadata(runId, product, slugify(product), version, vendor, projectUrl, license, publishedAt, null),
                new ReportScorecard(coreScore, colourGradient,
                        coreScore >= de.palsoftware.scim.validator.ui.service.ComplianceScoreService.DEFAULT_MIN_PUBLISH_SCORE,
                        normativeBreakdown, capabilityBreakdown,
                        null, null, null, traceabilityMatrix),
                testResults
        );
    }

    // Direct accessors to satisfy both flat model interface and structured JSON schema
    public String product() {
        return metadata != null ? metadata.productName() : null;
    }

    public String version() {
        return metadata != null ? metadata.productVersion() : null;
    }

    public String vendor() {
        return metadata != null ? metadata.vendorName() : null;
    }

    public String projectUrl() {
        return metadata != null ? metadata.projectUrl() : null;
    }

    public String license() {
        return metadata != null ? metadata.licenseType() : null;
    }

    public String publishedAt() {
        return metadata != null ? metadata.publishedAt() : null;
    }

    public String runId() {
        return metadata != null ? metadata.runId() : null;
    }

    public int coreScore() {
        return scorecard != null ? scorecard.coreScore() : 0;
    }

    public ColourGradientInfo colourGradient() {
        return scorecard != null ? scorecard.colourGradient() : null;
    }

    public NormativeLevelBreakdown normativeBreakdown() {
        return scorecard != null ? scorecard.normativeBreakdown() : null;
    }

    public List<CapabilityStatus> capabilityBreakdown() {
        return scorecard != null && scorecard.capabilities() != null
                ? scorecard.capabilities()
                : Collections.emptyList();
    }

    public List<RequirementTraceResult> traceabilityMatrix() {
        return scorecard != null && scorecard.requirementMatrix() != null
                ? scorecard.requirementMatrix()
                : Collections.emptyList();
    }

    /**
     * Linear-time O(n) slugifier that avoids polynomial regular expressions on user input.
     */
    public static String slugify(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }
        String lower = input.trim().toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder(lower.length());
        boolean prevHyphen = false;
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                sb.append(c);
                prevHyphen = false;
            } else if (!sb.isEmpty() && !prevHyphen) {
                sb.append('-');
                prevHyphen = true;
            }
        }
        if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == '-') {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ReportMetadata(
            @JsonProperty("runId") String runId,
            @JsonProperty("productName") String productName,
            @JsonProperty("productSlug") String productSlug,
            @JsonProperty("productVersion") String productVersion,
            @JsonProperty("vendorName") String vendorName,
            @JsonProperty("projectUrl") String projectUrl,
            @JsonProperty("licenseType") String licenseType,
            @JsonProperty("publishedAt") String publishedAt,
            @JsonProperty("submitter") String submitter,
            @JsonProperty("isSampleFixture") Boolean isSampleFixture
    ) {
        public ReportMetadata(
                String runId,
                String productName,
                String productSlug,
                String productVersion,
                String vendorName,
                String projectUrl,
                String licenseType,
                String publishedAt,
                String submitter) {
            this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                    licenseType, publishedAt, submitter, null);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ReportScorecard(
            @JsonProperty("coreScore") int coreScore,
            @JsonProperty("colourGradient") ColourGradientInfo colourGradient,
            @JsonProperty("publishEligible") boolean publishEligible,
            @JsonProperty("normativeBreakdown") NormativeLevelBreakdown normativeBreakdown,
            @JsonProperty("capabilities") List<CapabilityStatus> capabilities,
            @JsonProperty("capabilitySummary") CapabilitySummary capabilitySummary,
            @JsonProperty("requirementCounts") RequirementCounts requirementCounts,
            @JsonProperty("rfcSummaries") Map<String, RfcSectionSummary> rfcSummaries,
            @JsonProperty("requirementMatrix") List<RequirementTraceResult> requirementMatrix
    ) {
        public ReportScorecard {
            if (capabilities == null) {
                capabilities = Collections.emptyList();
            } else {
                capabilities = Collections.unmodifiableList(capabilities);
            }
            if (rfcSummaries == null) {
                rfcSummaries = Collections.emptyMap();
            } else {
                rfcSummaries = Collections.unmodifiableMap(rfcSummaries);
            }
            if (requirementMatrix == null) {
                requirementMatrix = Collections.emptyList();
            } else {
                requirementMatrix = Collections.unmodifiableList(requirementMatrix);
            }
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record NormativeLevelBreakdown(
            @JsonProperty("must") NormativeBreakdown must,
            @JsonProperty("should") NormativeBreakdown should,
            @JsonProperty("may") NormativeBreakdown may
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CapabilitySummary(
            @JsonProperty("supportedCount") int supportedCount,
            @JsonProperty("compliantCount") int compliantCount,
            @JsonProperty("totalCount") int totalCount
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RequirementCounts(
            @JsonProperty("catalogTotal") int catalogTotal,
            @JsonProperty("activeScopeCount") int activeScopeCount,
            @JsonProperty("excludedCount") int excludedCount,
            @JsonProperty("untestedCount") int untestedCount
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SanitizedTestResult(
            @JsonProperty("testId") String testId,
            @JsonProperty("displayName") String displayName,
            @JsonProperty("className") String className,
            @JsonProperty("testName") String testName,
            @JsonProperty("status") String status,
            @JsonProperty("durationMs") long durationMs,
            @JsonProperty("errorMessage") String errorMessage
    ) {}
}
