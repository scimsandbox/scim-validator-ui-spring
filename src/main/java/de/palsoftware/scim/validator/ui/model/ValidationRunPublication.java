package de.palsoftware.scim.validator.ui.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.springframework.data.domain.Persistable;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "validation_run_publication")
public class ValidationRunPublication implements Persistable<UUID> {

    public static final String PENDING_RESERVATION_PR_URL = "PENDING_RESERVATION";

    @Transient
    private boolean isNew = true;

    @Id
    @Column(name = "run_id")
    private UUID runId;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @MapsId
    @JoinColumn(name = "run_id", nullable = false)
    private ValidationRun run;

    @Column(name = "created_by_email", nullable = false, length = 500)
    private String createdByEmail;

    @Column(name = "product_name", nullable = false, length = 120)
    private String productName;

    @Column(name = "product_slug", nullable = false, length = 120)
    private String productSlug;

    @Column(name = "product_version", nullable = false, length = 60)
    private String productVersion;

    @Column(name = "vendor_name", length = 120)
    private String vendorName;

    @Column(name = "project_url", length = 500)
    private String projectUrl;

    @Column(name = "license_type", nullable = false, length = 40)
    private String licenseType;

    @Column(name = "show_submitter", nullable = false)
    private boolean showSubmitter = false;

    @Column(name = "core_score", nullable = false)
    private int coreScore;

    @Column(name = "supported_capabilities", nullable = false)
    private int supportedCapabilities;

    @Column(name = "total_capabilities", nullable = false)
    private int totalCapabilities;

    @Column(name = "report_url", nullable = false, length = 500)
    private String reportUrl;

    @Column(name = "badge_url", nullable = false, length = 500)
    private String badgeUrl;

    @Column(name = "pr_url", length = 500)
    private String prUrl;

    @Column(name = "published_at", nullable = false)
    private OffsetDateTime publishedAt;

    public ValidationRunPublication() {
    }

    public UUID getRunId() {
        return runId;
    }

    @Override
    public UUID getId() {
        return runId;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    @PostPersist
    @PostLoad
    public void markNotNew() {
        this.isNew = false;
    }

    @Transient
    public boolean isPendingReservation() {
        return PENDING_RESERVATION_PR_URL.equals(prUrl);
    }

    @Transient
    public boolean isStalePendingReservation(Duration timeout) {
        return isStalePendingReservation(OffsetDateTime.now(ZoneOffset.UTC), timeout);
    }

    @Transient
    public boolean isStalePendingReservation(OffsetDateTime now, Duration timeout) {
        if (!isPendingReservation()) {
            return false;
        }
        if (publishedAt == null) {
            return true;
        }
        Duration effectiveTimeout = (timeout != null && !timeout.isNegative() && !timeout.isZero())
                ? timeout
                : Duration.ofSeconds(300);
        OffsetDateTime referenceNow = now != null ? now : OffsetDateTime.now(ZoneOffset.UTC);
        return !publishedAt.plus(effectiveTimeout).isAfter(referenceNow);
    }

    public void setRunId(UUID runId) {
        this.runId = runId;
    }

    public ValidationRun getRun() {
        return run;
    }

    public void setRun(ValidationRun run) {
        this.run = run;
        if (run != null) {
            this.runId = run.getId();
        }
    }

    public String getCreatedByEmail() {
        return createdByEmail;
    }

    public void setCreatedByEmail(String createdByEmail) {
        this.createdByEmail = createdByEmail;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getProductSlug() {
        return productSlug;
    }

    public void setProductSlug(String productSlug) {
        this.productSlug = productSlug;
    }

    public String getProductVersion() {
        return productVersion;
    }

    public void setProductVersion(String productVersion) {
        this.productVersion = productVersion;
    }

    public String getVendorName() {
        return vendorName;
    }

    public void setVendorName(String vendorName) {
        this.vendorName = vendorName;
    }

    public String getProjectUrl() {
        return projectUrl;
    }

    public void setProjectUrl(String projectUrl) {
        this.projectUrl = projectUrl;
    }

    public String getLicenseType() {
        return licenseType;
    }

    public void setLicenseType(String licenseType) {
        this.licenseType = licenseType;
    }

    public boolean isShowSubmitter() {
        return showSubmitter;
    }

    public void setShowSubmitter(boolean showSubmitter) {
        this.showSubmitter = showSubmitter;
    }

    public int getCoreScore() {
        return coreScore;
    }

    public void setCoreScore(int coreScore) {
        this.coreScore = coreScore;
    }

    public int getSupportedCapabilities() {
        return supportedCapabilities;
    }

    public void setSupportedCapabilities(int supportedCapabilities) {
        this.supportedCapabilities = supportedCapabilities;
    }

    public int getTotalCapabilities() {
        return totalCapabilities;
    }

    public void setTotalCapabilities(int totalCapabilities) {
        this.totalCapabilities = totalCapabilities;
    }

    public String getReportUrl() {
        return reportUrl;
    }

    public void setReportUrl(String reportUrl) {
        this.reportUrl = reportUrl;
    }

    public String getBadgeUrl() {
        return badgeUrl;
    }

    public void setBadgeUrl(String badgeUrl) {
        this.badgeUrl = badgeUrl;
    }

    public String getPrUrl() {
        return prUrl;
    }

    public void setPrUrl(String prUrl) {
        this.prUrl = prUrl;
    }

    public OffsetDateTime getPublishedAt() {
        return publishedAt;
    }

    public void setPublishedAt(OffsetDateTime publishedAt) {
        this.publishedAt = publishedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ValidationRunPublication that)) return false;
        return runId != null && Objects.equals(runId, that.getRunId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
