package de.palsoftware.scim.validator.ui.dto;

import java.util.UUID;

public record ValidationProgress(
        UUID runId,
        String status,
        int currentTestIndex,
        int totalTests,
        int remainingTests,
        int percent,
        int passedTests,
        int failedTests,
        String currentSpec,
        String currentTestName,
        String errorMessage,
        String redirectUrl
) {
    public static ValidationProgress initial(UUID runId, int totalTests, String redirectUrl) {
        return new ValidationProgress(
                runId,
                "RUNNING",
                0,
                totalTests,
                totalTests,
                0,
                0,
                0,
                "",
                "Initializing tests...",
                null,
                redirectUrl
        );
    }

    public static ValidationProgress running(
            UUID runId,
            int currentTestIndex,
            int totalTests,
            int passedTests,
            int failedTests,
            String currentSpec,
            String currentTestName,
            String redirectUrl
    ) {
        int remaining = Math.max(0, totalTests - currentTestIndex);
        int percent = totalTests > 0 ? Math.min(100, (int) Math.round(((double) currentTestIndex / totalTests) * 100.0)) : 0;
        return new ValidationProgress(
                runId,
                "RUNNING",
                currentTestIndex,
                totalTests,
                remaining,
                percent,
                passedTests,
                failedTests,
                currentSpec != null ? currentSpec : "",
                currentTestName != null ? currentTestName : "",
                null,
                redirectUrl
        );
    }

    public static ValidationProgress completed(
            UUID runId,
            String status,
            int totalTests,
            int passedTests,
            int failedTests,
            String redirectUrl
    ) {
        return new ValidationProgress(
                runId,
                status,
                totalTests,
                totalTests,
                0,
                100,
                passedTests,
                failedTests,
                "",
                "Validation completed",
                null,
                redirectUrl
        );
    }

    public static ValidationProgress error(
            UUID runId,
            int currentTestIndex,
            int totalTests,
            int passedTests,
            int failedTests,
            String errorMessage,
            String redirectUrl
    ) {
        int percent = totalTests > 0 ? Math.min(100, (int) Math.round(((double) currentTestIndex / totalTests) * 100.0)) : 0;
        int remaining = Math.max(0, totalTests - currentTestIndex);
        return new ValidationProgress(
                runId,
                "ERROR",
                currentTestIndex,
                totalTests,
                remaining,
                percent,
                passedTests,
                failedTests,
                "",
                "Error occurred",
                errorMessage,
                redirectUrl
        );
    }
}
