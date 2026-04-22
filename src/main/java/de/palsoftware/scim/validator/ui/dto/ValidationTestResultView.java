package de.palsoftware.scim.validator.ui.dto;

import de.palsoftware.scim.validator.ui.model.ValidationTestResult;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record ValidationTestResultView(
    UUID id,
    String className,
    String testName,
    String displayName,
    String status,
    String errorMessage,
    String stackTrace,
    OffsetDateTime startedAt,
    OffsetDateTime finishedAt,
    List<ValidationHttpExchangeView> exchanges
) {
    public static ValidationTestResultView from(ValidationTestResult testResult, List<ValidationHttpExchangeView> exchanges) {
        return new ValidationTestResultView(
            testResult.getId(),
            testResult.getClassName(),
            testResult.getTestName(),
            testResult.getDisplayName(),
            testResult.getStatus(),
            testResult.getErrorMessage(),
            testResult.getStackTrace(),
            testResult.getStartedAt(),
            testResult.getFinishedAt(),
            exchanges
        );
    }
}
