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

    @Test
    void subscribe_whenRunStatusIsPartial_treatsAsTerminalComplete() {
        UUID runId = UUID.randomUUID();
        tracker.registerRun(runId, 280, "/runs/" + runId);
        tracker.completeRun(runId, "PARTIAL", 280, 276, 0);

        ValidationProgress progress = tracker.getProgress(runId);
        assertThat(progress).isNotNull();
        assertThat(progress.status()).isEqualTo("PARTIAL");
        assertThat(progress.percent()).isEqualTo(100);
        assertThat(progress.currentTestName()).isEqualTo("Validation completed");

        SseEmitter emitter = tracker.subscribe(runId);
        assertThat(emitter).isNotNull();
    }

    @Test
    void evictsExpiredTerminalAndStaleRunsAndBoundsTrackedSize() {
        long[] nowMs = {1_000L};
        ValidationProgressTracker bounded = new ValidationProgressTracker(3, 500L, () -> nowMs[0]);

        UUID run1 = UUID.randomUUID();
        UUID run2 = UUID.randomUUID();
        UUID run3 = UUID.randomUUID();
        bounded.registerRun(run1, 10, "/runs/" + run1);
        bounded.completeRun(run1, "PASSED", 10, 10, 0);

        nowMs[0] = 1_200L;
        bounded.registerRun(run2, 10, "/runs/" + run2);
        bounded.registerRun(run3, 10, "/runs/" + run3);
        assertThat(bounded.trackedCount()).isEqualTo(3);

        // Advance past terminal TTL (500ms) for run1
        nowMs[0] = 1_600L;
        assertThat(bounded.getProgress(run1)).isNull();
        assertThat(bounded.trackedCount()).isEqualTo(2);

        // Overflow beyond maxTrackedRuns=3 caps size at 3
        UUID run4 = UUID.randomUUID();
        UUID run5 = UUID.randomUUID();
        bounded.registerRun(run4, 10, "/runs/" + run4);
        bounded.registerRun(run5, 10, "/runs/" + run5);
        assertThat(bounded.trackedCount()).isEqualTo(3);

        // Advance past DEFAULT_STALE_RUNNING_TTL_MS -> stale running entries are evicted
        nowMs[0] = 1_600L + ValidationProgressTracker.DEFAULT_STALE_RUNNING_TTL_MS + 1_000L;
        assertThat(bounded.trackedCount()).isZero();
    }

    @Test
    void unregisteredRunOperationsNullProgressAndMaxEmittersEvictionWorkCleanly() {
        assertThat(tracker.getProgress(null)).isNull();

        // Calling updateProgress / completeRun / failRun before registerRun synthesizes fallback state
        UUID u1 = UUID.randomUUID();
        tracker.updateProgress(u1, 3, 10, 2, 1, "SpecA", "TestA");
        assertThat(tracker.getProgress(u1).redirectUrl()).isEqualTo("/runs/" + u1);

        UUID u2 = UUID.randomUUID();
        tracker.completeRun(u2, "FAILED", 10, 8, 2);
        assertThat(tracker.getProgress(u2).status()).isEqualTo("FAILED");
        assertThat(tracker.subscribe(u2)).isNotNull();

        UUID u3 = UUID.randomUUID();
        tracker.failRun(u3, "boom");
        assertThat(tracker.getProgress(u3).status()).isEqualTo("ERROR");
        assertThat(tracker.subscribe(u3)).isNotNull();

        UUID u4 = UUID.randomUUID();
        tracker.completeRun(u4, "PASSED", 5, 5, 0);
        assertThat(tracker.subscribe(u4)).isNotNull();

        // Subscribing > 16 emitters on one active run evicts oldest emitter cleanly
        UUID activeRun = UUID.randomUUID();
        tracker.registerRun(activeRun, 20, "/runs/" + activeRun);
        for (int i = 0; i < 18; i++) {
            assertThat(tracker.subscribe(activeRun)).isNotNull();
        }
        tracker.updateProgress(activeRun, 5, 20, 5, 0, "SpecB", "TestB");
        tracker.completeRun(activeRun, "PASSED", 20, 20, 0);
    }

    @Test
    void maxCapacityWithSingleSlotProtectsNewlyRegisteredRun() {
        ValidationProgressTracker singleSlot = new ValidationProgressTracker(1, 500L, () -> 1_000L);
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();

        singleSlot.registerRun(first, 10, "/runs/" + first);
        singleSlot.registerRun(second, 10, "/runs/" + second);

        assertThat(singleSlot.trackedCount()).isEqualTo(1);
        assertThat(singleSlot.getProgress(second)).isNotNull();
        assertThat(singleSlot.getProgress(first)).isNull();

        singleSlot.subscribe(second);
        singleSlot.removeRun(null);
        assertThat(singleSlot.getProgress(second)).isNotNull();
        singleSlot.removeRun(second);
        assertThat(singleSlot.getProgress(second)).isNull();
        assertThat(singleSlot.trackedCount()).isZero();
    }
}
