package de.palsoftware.scim.validator.ui.model.spec;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public record ComplianceScorecardView(
        UUID runId,
        String runName,
        String targetUrl,
        OffsetDateTime executedAt,
        String runStatus,
        int coreScore,
        ColourGradient colourGradient,
        boolean publishEligible,
        String publishIneligibilityReason,

        // Normative Level Breakdown
        NormativeBreakdown mustBreakdown,
        NormativeBreakdown shouldBreakdown,
        NormativeBreakdown mayBreakdown,

        // Capability Coverage
        List<CapabilityStatus> capabilities,
        int supportedCapabilitiesCount,
        int compliantCapabilitiesCount,
        int totalCapabilitiesCount,

        // Requirement Counts
        int catalogRequirementsTotal,
        int activeRequirementsCount,
        int excludedRequirementsCount,
        int untestedRequirementsCount,

        // Per-RFC Summaries
        Map<String, RfcSectionSummary> rfcSummaries,

        // Requirement Traceability Matrix
        List<RequirementTraceResult> requirementMatrix,

        // Core-Only Conformance (TASK-63) & Conformance Tier (Policy 3.3)
        int coreOnlyScore,
        double coreOnlyEarnedPoints,
        double coreOnlyTotalPoints,
        int coreCoveragePercent,
        String conformanceTierLabel
) {
    public ComplianceScorecardView {
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
        if (conformanceTierLabel == null || conformanceTierLabel.isBlank()) {
            conformanceTierLabel = computeConformanceTierLabel(coreScore, coreCoveragePercent, mustBreakdown);
        }
    }

    public ComplianceScorecardView(
            UUID runId,
            String runName,
            String targetUrl,
            OffsetDateTime executedAt,
            String runStatus,
            int coreScore,
            ColourGradient colourGradient,
            boolean publishEligible,
            String publishIneligibilityReason,
            NormativeBreakdown mustBreakdown,
            NormativeBreakdown shouldBreakdown,
            NormativeBreakdown mayBreakdown,
            List<CapabilityStatus> capabilities,
            int supportedCapabilitiesCount,
            int compliantCapabilitiesCount,
            int totalCapabilitiesCount,
            int catalogRequirementsTotal,
            int activeRequirementsCount,
            int excludedRequirementsCount,
            int untestedRequirementsCount,
            Map<String, RfcSectionSummary> rfcSummaries,
            List<RequirementTraceResult> requirementMatrix
    ) {
        this(
                runId, runName, targetUrl, executedAt, runStatus,
                coreScore, colourGradient, publishEligible, publishIneligibilityReason,
                mustBreakdown, shouldBreakdown, mayBreakdown,
                capabilities, supportedCapabilitiesCount, compliantCapabilitiesCount, totalCapabilitiesCount,
                catalogRequirementsTotal, activeRequirementsCount, excludedRequirementsCount, untestedRequirementsCount,
                rfcSummaries, requirementMatrix,
                coreScore, 0.0, 0.0,
                activeRequirementsCount > 0 ? 100 : 0,
                computeConformanceTierLabel(coreScore, activeRequirementsCount > 0 ? 100 : 0, mustBreakdown)
        );
    }

    public ComplianceScorecardView(
            UUID runId,
            String runName,
            String targetUrl,
            OffsetDateTime executedAt,
            String runStatus,
            int coreScore,
            ColourGradient colourGradient,
            boolean publishEligible,
            String publishIneligibilityReason,
            NormativeBreakdown mustBreakdown,
            NormativeBreakdown shouldBreakdown,
            NormativeBreakdown mayBreakdown,
            List<CapabilityStatus> capabilities,
            int supportedCapabilitiesCount,
            int compliantCapabilitiesCount,
            int totalCapabilitiesCount,
            int catalogRequirementsTotal,
            int activeRequirementsCount,
            int excludedRequirementsCount,
            int untestedRequirementsCount,
            Map<String, RfcSectionSummary> rfcSummaries,
            List<RequirementTraceResult> requirementMatrix,
            int coreOnlyScore,
            double coreOnlyEarnedPoints,
            double coreOnlyTotalPoints,
            String conformanceTierLabel
    ) {
        this(
                runId, runName, targetUrl, executedAt, runStatus,
                coreScore, colourGradient, publishEligible, publishIneligibilityReason,
                mustBreakdown, shouldBreakdown, mayBreakdown,
                capabilities, supportedCapabilitiesCount, compliantCapabilitiesCount, totalCapabilitiesCount,
                catalogRequirementsTotal, activeRequirementsCount, excludedRequirementsCount, untestedRequirementsCount,
                rfcSummaries, requirementMatrix,
                coreOnlyScore, coreOnlyEarnedPoints, coreOnlyTotalPoints,
                activeRequirementsCount > 0 ? 100 : 0,
                conformanceTierLabel
        );
    }

    public static String computeConformanceTierLabel(int coreScore, int coreCoveragePercent, NormativeBreakdown mustBreakdown) {
        boolean zeroMustFailed = mustBreakdown == null || mustBreakdown.failedRequirements() == 0;
        if (coreScore == 100 && coreCoveragePercent == 100 && zeroMustFailed) {
            return "Certified RFC Compliant";
        }
        if (coreScore >= 95) {
            return "Excellent Conformance";
        }
        return ColourGradient.forScore(coreScore).getLabel();
    }

    public String getFormattedNormativePoints() {
        if (mustBreakdown == null || shouldBreakdown == null || mayBreakdown == null) {
            return "0 / 0";
        }
        double earned = mustBreakdown.earnedPoints() + shouldBreakdown.earnedPoints() + mayBreakdown.earnedPoints();
        double total = mustBreakdown.totalPoints() + shouldBreakdown.totalPoints() + mayBreakdown.totalPoints();
        return formatPointsPair(earned, total);
    }

    public String formattedNormativePoints() {
        return getFormattedNormativePoints();
    }

    public String getFormattedCoreOnlyPoints() {
        return formatPointsPair(coreOnlyEarnedPoints, coreOnlyTotalPoints);
    }

    public String formattedCoreOnlyPoints() {
        return getFormattedCoreOnlyPoints();
    }

    public static String formatPointsPair(double earned, double total) {
        String totalStr = String.format(Locale.ROOT, "%.0f", total);
        if (Math.abs(earned - Math.rint(earned)) < 1e-9 && (earned >= total || Math.round(earned) < Math.round(total))) {
            return String.format(Locale.ROOT, "%.0f / %s", earned, totalStr);
        }
        double displayEarned = earned;
        if (earned < total && Math.round(earned * 10.0) / 10.0 >= total) {
            displayEarned = Math.floor(earned * 10.0) / 10.0;
        }
        return String.format(Locale.ROOT, "%.1f / %s", displayEarned, totalStr);
    }

    public String getScoreBadgeText() {
        return coreScore + "%";
    }

    public String getCapabilityBadgeText() {
        return compliantCapabilitiesCount + "/" + totalCapabilitiesCount + " caps";
    }
}
