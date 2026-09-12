package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ValidationProgressTrackerTest {

    private ValidationProgressTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new ValidationProgressTracker();
    }

    @Test
    void registerRun_storesInitialProgress() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 50, "/runs/" + runId);

        ValidationProgress progress = tracker.getProgress(runId);
        assertThat(progress).isNotNull();
        assertThat(progress.runId()).isEqualTo(runId);
        assertThat(progress.status()).isEqualTo("RUNNING");
        assertThat(progress.totalTests()).isEqualTo(50);
        assertThat(progress.remainingTests()).isEqualTo(50);
        assertThat(progress.currentTestIndex()).isZero();
    }

    @Test
    void updateProgress_updatesProgressState() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 50, "/runs/" + runId);

        tracker.updateProgress(runId, 10, 50, 9, 1, "A3_UserCrudSpec", "Test User");

        ValidationProgress progress = tracker.getProgress(runId);
        assertThat(progress).isNotNull();
        assertThat(progress.currentTestIndex()).isEqualTo(10);
        assertThat(progress.remainingTests()).isEqualTo(40);
        assertThat(progress.percent()).isEqualTo(20);
        assertThat(progress.passedTests()).isEqualTo(9);
        assertThat(progress.failedTests()).isEqualTo(1);
        assertThat(progress.currentSpec()).isEqualTo("A3_UserCrudSpec");
        assertThat(progress.currentTestName()).isEqualTo("Test User");
    }

    @Test
    void completeRun_setsFinalState() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 50, "/runs/" + runId);

        tracker.completeRun(runId, "PASSED", 50, 50, 0);

        ValidationProgress progress = tracker.getProgress(runId);
        assertThat(progress).isNotNull();
        assertThat(progress.status()).isEqualTo("PASSED");
        assertThat(progress.failedTests()).isZero();
        assertThat(progress.percent()).isEqualTo(100);
        assertThat(progress.remainingTests()).isZero();
    }

    @Test
    void discoverTestCount_findsTestsFromScimValidator() {
        ValidationRunService realService = new ValidationRunService(null, null, null, null, new ValidationProgressTracker(), null);
        int count = realService.discoverTestCount("http://localhost:8080/ws/test/scim/v2", "test-token");
        assertThat(count).isGreaterThanOrEqualTo(180);
    }

    @Test
    void failRun_capturesErrorMessage() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 50, "/runs/" + runId);

        tracker.failRun(runId, "Server unreachable");

        ValidationProgress progress = tracker.getProgress(runId);
        assertThat(progress).isNotNull();
        assertThat(progress.status()).isEqualTo("ERROR");
        assertThat(progress.errorMessage()).isEqualTo("Server unreachable");
    }

    @Test
    void subscribe_returnsSseEmitter() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 50, "/runs/" + runId);

        SseEmitter emitter = tracker.subscribe(runId);
        assertThat(emitter).isNotNull();
    }
}
