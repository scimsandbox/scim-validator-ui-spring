package de.palsoftware.scim.validator.ui.model.spec;

public enum CapabilitySupportLevel {
    SUPPORTED_COMPLIANT("Supported & Compliant", "success", "#10b981"),
    SUPPORTED_PARTIAL("Supported (Partial)", "warning", "#f59e0b"),
    UNSUPPORTED("Unsupported", "secondary", "#6b7280");

    private final String label;
    private final String badgeClass;
    private final String hexColor;

    CapabilitySupportLevel(String label, String badgeClass, String hexColor) {
        this.label = label;
        this.badgeClass = badgeClass;
        this.hexColor = hexColor;
    }

    public String getLabel() {
        return label;
    }

    public String getBadgeClass() {
        return badgeClass;
    }

    public String getHexColor() {
        return hexColor;
    }
}
