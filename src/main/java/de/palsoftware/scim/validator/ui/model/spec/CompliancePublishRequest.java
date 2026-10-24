package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CompliancePublishRequest(
        @JsonProperty("runId") UUID runId,
        @JsonProperty("productName") String productName,
        @JsonProperty("productSlug") String productSlug,
        @JsonProperty("productVersion") String productVersion,
        @JsonProperty("vendorName") String vendorName,
        @JsonProperty("projectUrl") String projectUrl,
        @JsonProperty("licenseType") String licenseType,
        @JsonProperty("showSubmitter") boolean showSubmitter,
        @JsonProperty("coreScore") int coreScore,
        @JsonProperty("colourGradient") String colourGradient,
        @JsonProperty("supportedCapabilities") int supportedCapabilities,
        @JsonProperty("totalCapabilities") int totalCapabilities,
        @JsonProperty("actorEmail") String actorEmail,
        @JsonProperty("targetUrl") String targetUrl,
        @JsonIgnore ComplianceScorecardView scorecard
) {
    public CompliancePublishRequest(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            boolean showSubmitter,
            int coreScore,
            String colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String actorEmail,
            String targetUrl) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, showSubmitter, coreScore, colourGradient, supportedCapabilities, totalCapabilities, actorEmail, targetUrl, null);
    }

    public CompliancePublishRequest(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            boolean showSubmitter,
            int coreScore,
            String colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String actorEmail) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, showSubmitter, coreScore, colourGradient, supportedCapabilities, totalCapabilities, actorEmail, null, null);
    }

    public CompliancePublishRequest(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            int coreScore,
            String colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String actorEmail) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, false, coreScore, colourGradient, supportedCapabilities, totalCapabilities, actorEmail, null, null);
    }

    public CompliancePublishRequest(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            boolean showSubmitter,
            int coreScore,
            String colourGradient,
            int supportedCapabilities,
            int totalCapabilities) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, showSubmitter, coreScore, colourGradient, supportedCapabilities, totalCapabilities, null, null, null);
    }

    public CompliancePublishRequest(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            int coreScore,
            String colourGradient,
            int supportedCapabilities,
            int totalCapabilities) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, false, coreScore, colourGradient, supportedCapabilities, totalCapabilities, null, null, null);
    }

    public CompliancePublishRequest withTargetUrl(String targetUrl) {
        return new CompliancePublishRequest(
                runId(), productName(), productSlug(), productVersion(), vendorName(),
                projectUrl(), licenseType(), showSubmitter(), coreScore(), colourGradient(),
                supportedCapabilities(), totalCapabilities(), actorEmail(), targetUrl, scorecard());
    }

    public CompliancePublishRequest withScorecard(ComplianceScorecardView scorecard) {
        return new CompliancePublishRequest(
                runId(), productName(), productSlug(), productVersion(), vendorName(),
                projectUrl(), licenseType(), showSubmitter(), coreScore(), colourGradient(),
                supportedCapabilities(), totalCapabilities(), actorEmail(), targetUrl(), scorecard);
    }
}
