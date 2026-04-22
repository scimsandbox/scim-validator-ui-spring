package de.palsoftware.scim.validator.ui.dto;

import de.palsoftware.scim.validator.ui.model.ValidationRun;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ValidationRunView(
        UUID id,
        String name,
        String targetUrl,
        OffsetDateTime executedAt,
        String status,
        String createdByEmail,
        int totalTests,
        int passedTests,
        int failedTests) {
    public static ValidationRunView from(ValidationRun run) {
        return new ValidationRunView(
                run.getId(),
                run.getName(),
                run.getTargetUrl(),
                run.getExecutedAt(),
                run.getStatus(),
                run.getCreatedByUser().getEmail(),
                run.getTotalTests(),
                run.getPassedTests(),
                run.getFailedTests());
    }
}
