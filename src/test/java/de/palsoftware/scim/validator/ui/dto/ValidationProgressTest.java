package de.palsoftware.scim.validator.ui.dto;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ValidationProgressTest {

    @Test
    void initial_createsCorrectDefaultValues() {
        UUID runId = UUID.randomUUID();
        ValidationProgress progress = ValidationProgress.initial(runId, 50, "/runs/" + runId);

        assertThat(progress.runId()).isEqualTo(runId);
        assertThat(progress.status()).isEqualTo("RUNNING");
        assertThat(progress.currentTestIndex()).isZero();
        assertThat(progress.totalTests()).isEqualTo(50);
        assertThat(progress.remainingTests()).isEqualTo(50);
        assertThat(progress.percent()).isZero();
        assertThat(progress.passedTests()).isZero();
        assertThat(progress.failedTests()).isZero();
        assertThat(progress.currentSpec()).isEmpty();
        assertThat(progress.currentTestName()).isEqualTo("Initializing tests...");
        assertThat(progress.errorMessage()).isNull();
        assertThat(progress.redirectUrl()).isEqualTo("/runs/" + runId);
    }

    @Test
    void running_calculatesRemainingAndPercentage() {
        UUID runId = UUID.randomUUID();
        ValidationProgress progress = ValidationProgress.running(
                runId,
                15,
                50,
                14,
                1,
                "A3_UserCrudSpec",
                "User can be created",
                "/runs/" + runId
        );

        assertThat(progress.currentTestIndex()).isEqualTo(15);
        assertThat(progress.totalTests()).isEqualTo(50);
        assertThat(progress.remainingTests()).isEqualTo(35);
        assertThat(progress.percent()).isEqualTo(30);
        assertThat(progress.passedTests()).isEqualTo(14);
        assertThat(progress.failedTests()).isEqualTo(1);
        assertThat(progress.currentSpec()).isEqualTo("A3_UserCrudSpec");
        assertThat(progress.currentTestName()).isEqualTo("User can be created");
    }

    @Test
    void completed_setsFullProgressAndStatus() {
        UUID runId = UUID.randomUUID();
        ValidationProgress progress = ValidationProgress.completed(
                runId,
                "PASSED",
                52,
                52,
                0,
                "/runs/" + runId
        );

        assertThat(progress.status()).isEqualTo("PASSED");
        assertThat(progress.currentTestIndex()).isEqualTo(52);
        assertThat(progress.remainingTests()).isZero();
        assertThat(progress.percent()).isEqualTo(100);
        assertThat(progress.passedTests()).isEqualTo(52);
        assertThat(progress.failedTests()).isZero();
        assertThat(progress.currentTestName()).isEqualTo("Validation completed");
    }

    @Test
    void error_capturesMessageAndMaintainsProgress() {
        UUID runId = UUID.randomUUID();
        ValidationProgress progress = ValidationProgress.error(
                runId,
                10,
                50,
                9,
                1,
                "Connection timeout",
                "/runs/" + runId
        );

        assertThat(progress.status()).isEqualTo("ERROR");
        assertThat(progress.currentTestIndex()).isEqualTo(10);
        assertThat(progress.remainingTests()).isEqualTo(40);
        assertThat(progress.percent()).isEqualTo(20);
        assertThat(progress.errorMessage()).isEqualTo("Connection timeout");
    }
}
