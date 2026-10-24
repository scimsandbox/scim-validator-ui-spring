package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ComplianceCatalogEntry(
        @JsonProperty("runId") UUID runId,
        @JsonProperty("productName") String productName,
        @JsonProperty("productSlug") String productSlug,
        @JsonProperty("productVersion") String productVersion,
        @JsonProperty("vendorName") String vendorName,
        @JsonProperty("projectUrl") String projectUrl,
        @JsonProperty("licenseType") String licenseType,
        @JsonProperty("coreScore") int coreScore,
        @JsonProperty("colourGradient") ColourGradientInfo colourGradient,
        @JsonProperty("supportedCapabilities") int supportedCapabilities,
        @JsonProperty("totalCapabilities") int totalCapabilities,
        @JsonProperty("reportPath") String reportPath,
        @JsonProperty("badgePath") String badgePath,
        @JsonProperty("publishedAt") String publishedAt,
        @JsonProperty("isSampleFixture") Boolean isSampleFixture
) {
    public ComplianceCatalogEntry(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            int coreScore,
            ColourGradientInfo colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String reportPath,
            String badgePath,
            String publishedAt) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, coreScore, colourGradient, supportedCapabilities, totalCapabilities,
                reportPath, badgePath, publishedAt, null);
    }

    public ComplianceCatalogEntry(
            UUID runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            int coreScore,
            ColourGradientInfo colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String reportPath,
            String badgePath,
            OffsetDateTime publishedAt) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, coreScore, colourGradient, supportedCapabilities, totalCapabilities,
                reportPath, badgePath,
                publishedAt != null ? publishedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME) : null,
                null);
    }

    public ComplianceCatalogEntry(
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
            String reportPath,
            String badgePath,
            OffsetDateTime publishedAt) {
        this(runId, productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, coreScore, ColourGradientInfo.from(colourGradient, coreScore),
                supportedCapabilities, totalCapabilities, reportPath, badgePath, publishedAt);
    }

    public ComplianceCatalogEntry(
            String runId,
            String productName,
            String productSlug,
            String productVersion,
            String vendorName,
            String projectUrl,
            String licenseType,
            int coreScore,
            ColourGradientInfo colourGradient,
            int supportedCapabilities,
            int totalCapabilities,
            String reportPath,
            String badgePath,
            String publishedAt) {
        this(runId != null ? UUID.fromString(runId) : null,
                productName, productSlug, productVersion, vendorName, projectUrl,
                licenseType, coreScore, colourGradient, supportedCapabilities, totalCapabilities,
                reportPath, badgePath, publishedAt);
    }
}
