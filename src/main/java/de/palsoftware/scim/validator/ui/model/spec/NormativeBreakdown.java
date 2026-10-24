package de.palsoftware.scim.validator.ui.model.spec;

public record NormativeBreakdown(
        String level,
        int weight,
        int activeRequirements,
        int compliantRequirements,
        int partialRequirements,
        int failedRequirements,
        double earnedPoints,
        double totalPoints,
        int conformancePercent
) {
    public static NormativeBreakdown of(
            String level,
            int weight,
            int activeRequirements,
            int compliantRequirements,
            int partialRequirements,
            int failedRequirements,
            double earnedPoints,
            double totalPoints) {
        int percent = totalPoints > 0 ? (int) Math.round((100.0 * earnedPoints) / totalPoints) : 100;
        return new NormativeBreakdown(
                level,
                weight,
                activeRequirements,
                compliantRequirements,
                partialRequirements,
                failedRequirements,
                earnedPoints,
                totalPoints,
                percent
        );
    }
}
