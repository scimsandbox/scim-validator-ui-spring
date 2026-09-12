package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class ValidationProgressTracker {

    private static final Logger log = LoggerFactory.getLogger(ValidationProgressTracker.class);
    private static final long SSE_TIMEOUT_MS = 5 * 60 * 1000L; // 5 minutes

    private final Map<UUID, ValidationProgress> progressMap = new ConcurrentHashMap<>();
    private final Map<UUID, List<SseEmitter>> emitterMap = new ConcurrentHashMap<>();

    public void registerRun(UUID runId, int totalTests, String redirectUrl) {
        ValidationProgress initial = ValidationProgress.initial(runId, totalTests, redirectUrl);
        progressMap.put(runId, initial);
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
        ValidationProgress existing = progressMap.get(runId);
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
        progressMap.put(runId, progress);
        broadcast(runId, "progress", progress);
    }

    public void completeRun(UUID runId, String status, int totalTests, int passedTests, int failedTests) {
        ValidationProgress existing = progressMap.get(runId);
        String redirectUrl = existing != null ? existing.redirectUrl() : "/runs/" + runId;
        ValidationProgress progress = ValidationProgress.completed(
                runId,
                status,
                totalTests,
                passedTests,
                failedTests,
                redirectUrl
        );
        progressMap.put(runId, progress);
        broadcast(runId, "complete", progress);
        closeEmitters(runId);
    }

    public void failRun(UUID runId, String errorMessage) {
        ValidationProgress existing = progressMap.get(runId);
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
        progressMap.put(runId, progress);
        broadcast(runId, "error", progress);
        closeEmitters(runId);
    }

    public ValidationProgress getProgress(UUID runId) {
        return progressMap.get(runId);
    }

    public SseEmitter subscribe(UUID runId) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        emitterMap.computeIfAbsent(runId, id -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(runId, emitter));
        emitter.onTimeout(() -> removeEmitter(runId, emitter));
        emitter.onError(throwable -> removeEmitter(runId, emitter));

        ValidationProgress current = progressMap.get(runId);
        if (current != null) {
            try {
                if ("PASSED".equals(current.status()) || "FAILED".equals(current.status())) {
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

        return emitter;
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
                try {
                    emitter.complete();
                } catch (Exception ignored) {
                }
            }
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
