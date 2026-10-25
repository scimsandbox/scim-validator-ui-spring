package de.palsoftware.scim.validator.ui.model.spec;

public record RfcSectionSummary(
        String rfc,
        String rfcTitle,
        int totalRequirements,
        int activeRequirements,
        int compliantRequirements,
        double earnedPoints,
        double totalPoints,
        int conformancePercent
) {}
