package de.palsoftware.scim.validator.ui.model.spec;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
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
        List<RequirementTraceResult> requirementMatrix
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
    }

    public String getScoreBadgeText() {
        return coreScore + "%";
    }

    public String getCapabilityBadgeText() {
        return compliantCapabilitiesCount + "/" + totalCapabilitiesCount + " caps";
    }
}
