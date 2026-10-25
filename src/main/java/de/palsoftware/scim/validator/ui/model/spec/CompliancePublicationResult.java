package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CompliancePublicationResult(
        @JsonProperty("success") boolean success,
        @JsonProperty("runId") UUID runId,
        @JsonProperty("prUrl") String prUrl,
        @JsonProperty("reportUrl") String reportUrl,
        @JsonProperty("badgeUrl") String badgeUrl,
        @JsonProperty("mergeCommitSha") String mergeCommitSha,
        @JsonProperty("errorMessage") String errorMessage,
        @JsonProperty("publishedAt") OffsetDateTime publishedAt,
        @JsonProperty("reconciledCatalogEntry") ComplianceCatalogEntry reconciledCatalogEntry
) {
    public CompliancePublicationResult(
            boolean success,
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            String errorMessage,
            OffsetDateTime publishedAt) {
        this(success, runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, errorMessage, publishedAt, null);
    }

    public CompliancePublicationResult(
            boolean success,
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            String errorMessage) {
        this(success, runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, errorMessage,
                success ? OffsetDateTime.now(ZoneOffset.UTC) : null, null);
    }

    public CompliancePublicationResult(
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            OffsetDateTime publishedAt) {
        this(true, runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, null, publishedAt, null);
    }

    public static CompliancePublicationResult success(
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            OffsetDateTime publishedAt) {
        return new CompliancePublicationResult(true, runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, null, publishedAt, null);
    }

    public static CompliancePublicationResult succeeded(
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            OffsetDateTime publishedAt) {
        return success(runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, publishedAt);
    }

    public static CompliancePublicationResult reconciled(
            UUID runId,
            String prUrl,
            String reportUrl,
            String badgeUrl,
            String mergeCommitSha,
            OffsetDateTime publishedAt,
            ComplianceCatalogEntry catalogEntry) {
        return new CompliancePublicationResult(
                true, runId, prUrl, reportUrl, badgeUrl, mergeCommitSha, null, publishedAt, catalogEntry);
    }

    public static CompliancePublicationResult failure(UUID runId, String errorMessage) {
        return new CompliancePublicationResult(false, runId, null, null, null, null, errorMessage, null, null);
    }
}
