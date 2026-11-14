package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.LongSupplier;

@Service
public class ValidationProgressTracker {

    private static final long SSE_TIMEOUT_MS = 5 * 60 * 1000L; // 5 minutes
    static final int DEFAULT_MAX_TRACKED_RUNS = 500;
    static final long DEFAULT_TERMINAL_TTL_MS = 15 * 60 * 1000L; // 15 minutes
    static final long DEFAULT_STALE_RUNNING_TTL_MS = 60 * 60 * 1000L; // 1 hour
    private static final int MAX_EMITTERS_PER_RUN = 16;

    private record TrackedEntry(ValidationProgress progress, long updatedAtMillis, boolean terminal) {}

    private final Map<UUID, TrackedEntry> progressMap = new ConcurrentHashMap<>();
    private final Map<UUID, List<SseEmitter>> emitterMap = new ConcurrentHashMap<>();
    private final int maxTrackedRuns;
    private final long terminalTtlMillis;
    private final LongSupplier clock;

    @Autowired
    public ValidationProgressTracker() {
        this(DEFAULT_MAX_TRACKED_RUNS, DEFAULT_TERMINAL_TTL_MS, System::currentTimeMillis);
    }

    public ValidationProgressTracker(int maxTrackedRuns, long terminalTtlMillis, LongSupplier clock) {
        this.maxTrackedRuns = Math.max(1, maxTrackedRuns);
        this.terminalTtlMillis = Math.max(1L, terminalTtlMillis);
        this.clock = Objects.requireNonNull(clock, "Clock supplier must not be null");
    }

    public void registerRun(UUID runId, int totalTests, String redirectUrl) {
        evictExpiredAndOverflow();
        ValidationProgress initial = ValidationProgress.initial(runId, totalTests, redirectUrl);
        progressMap.put(runId, new TrackedEntry(initial, clock.getAsLong(), false));
        enforceMaxCapacity(runId);
        broadcast(runId, "progress", initial);
    }

    public void updateProgress(
            UUID runId,
            int currentTestIndex,
            int totalTests,
            int passedTests,
            int failedTests,
            String currentSpec,
            String currentTestName
    ) {
        TrackedEntry existingEntry = progressMap.get(runId);
        ValidationProgress existing = existingEntry != null ? existingEntry.progress() : null;
        String redirectUrl = existing != null ? existing.redirectUrl() : "/runs/" + runId;
        ValidationProgress progress = ValidationProgress.running(
                runId,
                currentTestIndex,
                totalTests,
                passedTests,
                failedTests,
                currentSpec,
                currentTestName,
                redirectUrl
        );
        progressMap.put(runId, new TrackedEntry(progress, clock.getAsLong(), false));
        broadcast(runId, "progress", progress);
    }

    public void completeRun(UUID runId, String status, int totalTests, int passedTests, int failedTests) {
        TrackedEntry existingEntry = progressMap.get(runId);
        ValidationProgress existing = existingEntry != null ? existingEntry.progress() : null;
        String redirectUrl = existing != null ? existing.redirectUrl() : "/runs/" + runId;
        ValidationProgress progress = ValidationProgress.completed(
                runId,
                status,
                totalTests,
                passedTests,
                failedTests,
                redirectUrl
        );
        progressMap.put(runId, new TrackedEntry(progress, clock.getAsLong(), true));
        broadcast(runId, "complete", progress);
        closeEmitters(runId);
        evictExpiredAndOverflow();
    }

    public void failRun(UUID runId, String errorMessage) {
        TrackedEntry existingEntry = progressMap.get(runId);
        ValidationProgress existing = existingEntry != null ? existingEntry.progress() : null;
        int currentIndex = existing != null ? existing.currentTestIndex() : 0;
        int total = existing != null ? existing.totalTests() : 0;
        int passed = existing != null ? existing.passedTests() : 0;
        int failed = existing != null ? existing.failedTests() : 0;
        String redirectUrl = existing != null ? existing.redirectUrl() : "/runs/" + runId;

        ValidationProgress progress = ValidationProgress.error(
                runId,
                currentIndex,
                total,
                passed,
                failed,
                errorMessage,
                redirectUrl
        );
        progressMap.put(runId, new TrackedEntry(progress, clock.getAsLong(), true));
        broadcast(runId, "error", progress);
        closeEmitters(runId);
        evictExpiredAndOverflow();
    }

    public void removeRun(UUID runId) {
        if (runId == null) {
            return;
        }
        progressMap.remove(runId);
        closeEmitters(runId);
    }

    public ValidationProgress getProgress(UUID runId) {
        if (runId == null) {
            return null;
        }
        evictExpiredAndOverflow();
        TrackedEntry entry = progressMap.get(runId);
        return entry != null ? entry.progress() : null;
    }

    int trackedCount() {
        evictExpiredAndOverflow();
        return progressMap.size();
    }

    public SseEmitter subscribe(UUID runId) {
        evictExpiredAndOverflow();
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        List<SseEmitter> emitters = emitterMap.computeIfAbsent(runId, id -> new CopyOnWriteArrayList<>());
        while (emitters.size() >= MAX_EMITTERS_PER_RUN) {
            SseEmitter evicted = emitters.remove(0);
            completeQuietly(evicted);
        }
        emitters.add(emitter);

        emitter.onCompletion(() -> removeEmitter(runId, emitter));
        emitter.onTimeout(() -> removeEmitter(runId, emitter));
        emitter.onError(throwable -> removeEmitter(runId, emitter));

        TrackedEntry currentEntry = progressMap.get(runId);
        ValidationProgress current = currentEntry != null ? currentEntry.progress() : null;
        if (current != null) {
            sendInitialSnapshot(runId, emitter, current);
        }

        return emitter;
    }

    private void sendInitialSnapshot(UUID runId, SseEmitter emitter, ValidationProgress current) {
        try {
            if (isCompletedStatus(current.status())) {
                emitter.send(SseEmitter.event().name("complete").data(current));
                emitter.complete();
            } else if ("ERROR".equals(current.status())) {
                emitter.send(SseEmitter.event().name("error").data(current));
                emitter.complete();
            } else {
                emitter.send(SseEmitter.event().name("progress").data(current));
            }
        } catch (IOException ex) {
            removeEmitter(runId, emitter);
        }
    }

    private static boolean isCompletedStatus(String status) {
        return "PASSED".equals(status) || "FAILED".equals(status) || "PARTIAL".equals(status);
    }

    private void evictExpiredAndOverflow() {
        long now = clock.getAsLong();
        for (Map.Entry<UUID, TrackedEntry> entry : progressMap.entrySet()) {
            TrackedEntry tracked = entry.getValue();
            long age = now - tracked.updatedAtMillis();
            boolean expiredTerminal = tracked.terminal() && age >= terminalTtlMillis;
            boolean expiredRunning = !tracked.terminal() && age >= Math.max(terminalTtlMillis, DEFAULT_STALE_RUNNING_TTL_MS);
            if ((expiredTerminal || expiredRunning) && progressMap.remove(entry.getKey(), tracked)) {
                closeEmitters(entry.getKey());
            }
        }
        enforceMaxCapacity(null);
    }

    private void enforceMaxCapacity(UUID protectedRunId) {
        while (progressMap.size() > maxTrackedRuns) {
            UUID candidateKey = progressMap.entrySet().stream()
                    .filter(e -> !e.getKey().equals(protectedRunId))
                    .min(Comparator
                            .<Map.Entry<UUID, TrackedEntry>, Boolean>comparing(e -> !e.getValue().terminal())
                            .thenComparingLong(e -> e.getValue().updatedAtMillis()))
                    .map(Map.Entry::getKey)
                    .orElse(null);
            if (candidateKey == null) {
                break;
            }
            progressMap.remove(candidateKey);
            closeEmitters(candidateKey);
        }
    }

    private void broadcast(UUID runId, String eventName, Object data) {
        List<SseEmitter> emitters = emitterMap.get(runId);
        if (emitters == null || emitters.isEmpty()) {
            return;
        }

        List<SseEmitter> deadEmitters = new CopyOnWriteArrayList<>();
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(data));
            } catch (Exception ex) {
                deadEmitters.add(emitter);
            }
        }
        emitters.removeAll(deadEmitters);
    }

    private void closeEmitters(UUID runId) {
        List<SseEmitter> emitters = emitterMap.remove(runId);
        if (emitters != null) {
            for (SseEmitter emitter : emitters) {
                completeQuietly(emitter);
            }
        }
    }

    private static void completeQuietly(SseEmitter emitter) {
        try {
            emitter.complete();
        } catch (Exception ignored) {
            // Client already disconnected
        }
    }

    private void removeEmitter(UUID runId, SseEmitter emitter) {
        List<SseEmitter> emitters = emitterMap.get(runId);
        if (emitters != null) {
            emitters.remove(emitter);
            if (emitters.isEmpty()) {
                emitterMap.remove(runId);
            }
        }
    }
}
