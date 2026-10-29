package de.palsoftware.scim.validator.ui.model.spec;

import java.util.List;

public record RequirementTraceResult(
        String id,
        String rfc,
        String section,
        String title,
        String level,
        int weight,
        String capability,
        boolean inActiveScope,
        int totalTests,
        int executedTests,
        int passedTests,
        int failedTests,
        int abortedTests,
        double earnedWeight,
        String status,
        List<String> mappedTestIds
) {
    public String rfcUrl() {
        if (rfc == null || rfc.isBlank()) return null;
        if (section == null || section.isBlank()) {
            return "https://www.rfc-editor.org/rfc/rfc" + rfc;
        }
        return "https://www.rfc-editor.org/rfc/rfc" + rfc + "#section-" + section;
    }
}
