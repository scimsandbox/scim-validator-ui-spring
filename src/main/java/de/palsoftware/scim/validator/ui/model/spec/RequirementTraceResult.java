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
) {}
