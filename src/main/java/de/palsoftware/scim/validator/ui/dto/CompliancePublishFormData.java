package de.palsoftware.scim.validator.ui.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class CompliancePublishFormData {

    @NotBlank(message = "Product name is required")
    @Size(max = 120, message = "Product name cannot exceed 120 characters")
    private String productName;

    @NotBlank(message = "Product slug is required")
    @Size(max = 120, message = "Product slug cannot exceed 120 characters")
    @Pattern(regexp = "^[a-z0-9]+(?:-[a-z0-9]+)*$", message = "Product slug must only contain lowercase alphanumeric characters separated by single hyphens")
    private String productSlug;

    @NotBlank(message = "Product version is required")
    @Size(max = 60, message = "Product version cannot exceed 60 characters")
    private String productVersion;

    @Size(max = 120, message = "Vendor/organization name cannot exceed 120 characters")
    private String vendorName;

    @Size(max = 500, message = "Project URL cannot exceed 500 characters")
    @Pattern(regexp = "^(https?://.*)?$", message = "Project URL must be a valid HTTP or HTTPS URL")
    private String projectUrl;

    @NotBlank(message = "License type is required")
    @Size(max = 40, message = "License type cannot exceed 40 characters")
    private String licenseType = "Apache-2.0";

    private boolean showSubmitter = false;

    public CompliancePublishFormData() {
    }

    public CompliancePublishFormData(String productName, String productSlug, String productVersion,
                                   String vendorName, String projectUrl, String licenseType, boolean showSubmitter) {
        this.productName = productName;
        this.productSlug = productSlug;
        this.productVersion = productVersion;
        this.vendorName = vendorName;
        this.projectUrl = projectUrl;
        this.licenseType = licenseType != null ? licenseType : "Apache-2.0";
        this.showSubmitter = showSubmitter;
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

    /**
     * Resolves canonical URL slug from product name if slug was left blank or empty.
     */
    public String resolveProductSlug() {
        if (productSlug != null && !productSlug.isBlank()) {
            return productSlug.trim().toLowerCase();
        }
        if (productName != null && !productName.isBlank()) {
            return productName.trim().toLowerCase()
                    .replaceAll("[^a-z0-9]+", "-")
                    .replaceAll("^-+|-+$", "");
        }
        return "scim-server";
    }
}
