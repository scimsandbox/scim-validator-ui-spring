package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

public record RequirementTraceResult(
        String id,
        String rfc,
        String section,
        String title,
        @JsonIgnore String quote,
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
    public RequirementTraceResult(
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
        this(id, rfc, section, title, title, level, weight, capability, inActiveScope,
                totalTests, executedTests, passedTests, failedTests, abortedTests, earnedWeight, status, mappedTestIds);
    }

    public String rfcUrl() {
        return SpecRequirement.formatRfcUrl(rfc, section);
    }

    public String rfcLabel() {
        return SpecRequirement.formatRfcLabel(rfc, section);
    }
}
