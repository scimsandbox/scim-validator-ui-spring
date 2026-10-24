package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.base.ScimBaseSpec;
import de.palsoftware.scim.validator.base.ScimHttpExchange;
import de.palsoftware.scim.validator.base.ScimRunContext;
import de.palsoftware.scim.validator.base.ValidatorConfiguration;
import de.palsoftware.scim.validator.ui.dto.ValidationHttpExchangeView;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import de.palsoftware.scim.validator.ui.util.Slugifier;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

@Service
@Transactional(readOnly = true)
public class ValidationRunService {

    private static final Logger log = LoggerFactory.getLogger(ValidationRunService.class);

    private final ValidationRunRepository runRepository;
    private final ValidationMgmtUserRepository mgmtUserRepository;
    private final ValidationTestResultRepository testResultRepository;
    private final ValidationHttpExchangeRepository exchangeRepository;
    private final ValidationRunPublicationRepository publicationRepository;
    private final ValidationProgressTracker progressTracker;
    private final ExecutorService executorService;

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, null, new ValidationProgressTracker(), Executors.newCachedThreadPool());
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationProgressTracker progressTracker) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, null, progressTracker, Executors.newCachedThreadPool());
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationProgressTracker progressTracker,
            ExecutorService executorService) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, null, progressTracker, executorService);
    }

    @Autowired
    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker) {
        this(runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, publicationRepository, progressTracker, Executors.newCachedThreadPool());
    }

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository,
            ValidationRunPublicationRepository publicationRepository,
            ValidationProgressTracker progressTracker,
            ExecutorService executorService) {
        this.runRepository = runRepository;
        this.mgmtUserRepository = mgmtUserRepository;
        this.testResultRepository = testResultRepository;
        this.exchangeRepository = exchangeRepository;
        this.publicationRepository = publicationRepository;
        this.progressTracker = progressTracker != null ? progressTracker : new ValidationProgressTracker();
        this.executorService = executorService != null ? executorService : Executors.newCachedThreadPool();
    }

    @Value("${app.runs.max-per-user:10}")
    private int maxRunsPerUser = 10;

    @Value("${app.runs.max-published-per-user:50}")
    private int maxPublishedRunsPerUser = 50;

    @Value("${app.compliance.public-base-url:https://scimsandbox.net}")
    private String publicBaseUrl = "https://scimsandbox.net";

    @Value("${app.compliance.reservation-timeout-seconds:300}")
    private long reservationTimeoutSeconds = 300;

    public int getMaxRunsPerUser() {
        return maxRunsPerUser;
    }

    public int getMaxPublishedRunsPerUser() {
        return maxPublishedRunsPerUser;
    }

    public String getEffectivePublicBaseUrl() {
        String url = (publicBaseUrl != null && !publicBaseUrl.isBlank()) ? publicBaseUrl.trim() : "https://scimsandbox.net";
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public void setPublicBaseUrl(String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
    }

    public long getReservationTimeoutSeconds() {
        return reservationTimeoutSeconds;
    }

    public void setReservationTimeoutSeconds(long reservationTimeoutSeconds) {
        this.reservationTimeoutSeconds = reservationTimeoutSeconds;
    }

    public Duration getReservationTimeout() {
        return Duration.ofSeconds(Math.max(1L, reservationTimeoutSeconds));
    }

    public boolean isStaleReservation(ValidationRunPublication publication) {
        return publication != null && publication.isStalePendingReservation(getReservationTimeout());
    }

    public static class ExecutionResult {
        private final ValidationRun run;
        private final boolean oldRunDeleted;
        private final int maxRuns;

        public ExecutionResult(ValidationRun run, boolean oldRunDeleted, int maxRuns) {
            this.run = run;
            this.oldRunDeleted = oldRunDeleted;
            this.maxRuns = maxRuns;
        }

        public ValidationRun getRun() { return run; }
        public boolean isOldRunDeleted() { return oldRunDeleted; }
        public int getMaxRuns() { return maxRuns; }
    }

    private boolean pruneOldUnpublishedRuns(String actorEmail) {
        List<ValidationRun> userRuns = runRepository.findOwnedRuns(actorEmail, Sort.by(Sort.Direction.ASC, "executedAt"));
        boolean oldRunDeleted = false;

        if (userRuns.size() >= maxRunsPerUser) {
            int toDelete = userRuns.size() - maxRunsPerUser + 1;
            for (int i = 0; i < toDelete; i++) {
                ValidationRun runToDelete = userRuns.get(i);
                if (runToDelete.isPublished()) {
                    log.warn("Skipping deletion of published run {} during auto-pruning", runToDelete.getId());
                    continue;
                }
                if (runToDelete.hasPendingReservation()) {
                    if (!isStaleReservation(runToDelete.getPublication())) {
                        log.warn("Skipping deletion of run {} with active publication reservation during auto-pruning", runToDelete.getId());
                        continue;
                    }
                    releasePublicationReservation(runToDelete);
                }
                runRepository.delete(runToDelete);
                oldRunDeleted = true;
            }
        }
        return oldRunDeleted;
    }

    @Transactional
    public ExecutionResult executeRun(ValidationRunForm form, String actorEmail) {
        TargetUrlPolicy.validate(form.baseUrl());
        boolean oldRunDeleted = pruneOldUnpublishedRuns(actorEmail);

        int plannedTotal = discoverTestCount(form.baseUrl(), form.authToken());

        ValidationRun run = new ValidationRun();
        run.setName(form.name().trim());
        run.setTargetUrl(form.baseUrl().trim());
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("RUNNING");
        ValidationMgmtUser owner = mgmtUserRepository.findById(actorEmail)
                .orElseThrow(() -> new IllegalStateException("Authenticated management user must exist"));
        run.setCreatedByUser(owner);
        run.setTotalTests(plannedTotal);
        run.setPassedTests(0);
        run.setFailedTests(0);
        run = runRepository.save(run);

        UUID runId = run.getId();
        if (runId != null) {
            progressTracker.registerRun(runId, plannedTotal, "/runs/" + runId);
        }

        ValidationExecutionListener listener = null;
        try {
            ValidatorConfiguration.useRunOverrides(form.baseUrl(), form.authToken());
            ScimBaseSpec.resetRunState();
            if (runId != null) {
                ScimRunContext.beginRun(runId.toString());
            }

            listener = new ValidationExecutionListener(run, plannedTotal, progressTracker, testResultRepository,
                    exchangeRepository);
            Launcher launcher = LauncherFactory.create();
            executeLauncher(launcher, buildRequest(), listener);

            run.setTotalTests(listener.total);
            run.setPassedTests(listener.passed);
            run.setFailedTests(listener.failed);
            String finalStatus = listener.failed > 0 ? "FAILED" : "PASSED";
            run.setStatus(finalStatus);
            if (runId != null) {
                progressTracker.completeRun(runId, finalStatus, listener.total, listener.passed, listener.failed);
            }
        } catch (Exception ex) {
            log.error("Error executing validation run", ex);
            run.setStatus("ERROR");
            if (listener != null) {
                run.setTotalTests(listener.total);
                run.setPassedTests(listener.passed);
                run.setFailedTests(listener.failed);
            } else {
                run.setTotalTests(0);
            }
            if (runId != null) {
                progressTracker.failRun(runId, ex.getMessage() != null ? ex.getMessage() : "Execution error");
            }
        } finally {
            ScimRunContext.endRun();
            ScimBaseSpec.resetRunState();
            ValidatorConfiguration.clearRunOverrides();
        }

        return new ExecutionResult(runRepository.save(run), oldRunDeleted, maxRunsPerUser);
    }

    @Transactional
    public ExecutionResult executeRunAsync(ValidationRunForm form, String actorEmail) {
        TargetUrlPolicy.validate(form.baseUrl());
        boolean oldRunDeleted = pruneOldUnpublishedRuns(actorEmail);

        int plannedTotal = discoverTestCount(form.baseUrl(), form.authToken());

        ValidationRun run = new ValidationRun();
        run.setName(form.name().trim());
        run.setTargetUrl(form.baseUrl().trim());
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("RUNNING");
        ValidationMgmtUser owner = mgmtUserRepository.findById(actorEmail)
                .orElseThrow(() -> new IllegalStateException("Authenticated management user must exist"));
        run.setCreatedByUser(owner);
        run.setTotalTests(plannedTotal);
        run.setPassedTests(0);
        run.setFailedTests(0);
        run = runRepository.saveAndFlush(run);

        UUID runId = run.getId();
        if (runId != null) {
            progressTracker.registerRun(runId, plannedTotal, "/runs/" + runId);
            if (TransactionSynchronizationManager.isSynchronizationActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        executorService.submit(() -> runTestsInBackground(runId, form, plannedTotal));
                    }
                });
            } else {
                executorService.submit(() -> runTestsInBackground(runId, form, plannedTotal));
            }
        }

        return new ExecutionResult(run, oldRunDeleted, maxRunsPerUser);
    }

    void runTestsInBackground(UUID runId, ValidationRunForm form, int plannedTotal) {
        ValidationRun run = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            run = runRepository.findById(runId).orElse(null);
            if (run != null) {
                break;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        if (run == null) {
            log.error("Run not found for id {}", runId);
            progressTracker.failRun(runId, "Validation run could not be initialized");
            return;
        }

        ValidationExecutionListener listener = null;
        try {
            ValidatorConfiguration.useRunOverrides(form.baseUrl(), form.authToken());
            ScimBaseSpec.resetRunState();
            ScimRunContext.beginRun(runId.toString());

            listener = new ValidationExecutionListener(
                    run,
                    plannedTotal,
                    progressTracker,
                    testResultRepository,
                    exchangeRepository
            );

            Launcher launcher = LauncherFactory.create();
            executeLauncher(launcher, buildRequest(), listener);

            run.setTotalTests(listener.total);
            run.setPassedTests(listener.passed);
            run.setFailedTests(listener.failed);
            String finalStatus = listener.failed > 0 ? "FAILED" : "PASSED";
            run.setStatus(finalStatus);
            runRepository.save(run);

            progressTracker.completeRun(runId, finalStatus, listener.total, listener.passed, listener.failed);
        } catch (Throwable ex) {
            log.error("Error executing background validation run {}", runId, ex);
            run.setStatus("ERROR");
            if (listener != null) {
                run.setTotalTests(listener.total);
                run.setPassedTests(listener.passed);
                run.setFailedTests(listener.failed);
            } else {
                run.setTotalTests(0);
            }
            runRepository.save(run);
            progressTracker.failRun(runId, ex.getMessage() != null ? ex.getMessage() : "Execution error");
        } finally {
            ScimRunContext.endRun();
            ScimBaseSpec.resetRunState();
            ValidatorConfiguration.clearRunOverrides();
        }
    }

    public long countOwnedRuns(String actorEmail) {
        if (actorEmail == null) {
            return 0;
        }
        return runRepository.countOwnedRuns(actorEmail);
    }

    public List<ValidationRunView> listRuns(String actorEmail, boolean admin) {
        List<ValidationRun> runs;
        Sort sort = Sort.by(Sort.Direction.DESC, "executedAt");
        if (admin) {
            runs = runRepository.findAll(sort);
        } else {
            runs = runRepository.findOwnedRuns(actorEmail, sort);
        }
        return runs
                .stream()
                .map(r -> ValidationRunView.from(r, getReservationTimeout()))
                .toList();
    }

    public ValidationRunView getRun(UUID runId, String actorEmail, boolean admin) {
        ValidationRun run = requireRunAccess(runId, actorEmail, admin);
        return ValidationRunView.from(run, getReservationTimeout());
    }

    public List<ValidationTestResultView> getTestResults(UUID runId, String actorEmail, boolean admin) {
        requireRunAccess(runId, actorEmail, admin);
        List<ValidationTestResult> testResults = testResultRepository.findByRunIdOrderByStartedAtAsc(runId);
        return testResults.stream()
                .map(testResult -> {
                    List<ValidationHttpExchangeView> exchanges = exchangeRepository
                            .findByTestResultIdOrderBySequenceNumberAsc(testResult.getId())
                            .stream()
                            .map(ValidationHttpExchangeView::from)
                            .toList();
                    return ValidationTestResultView.from(testResult, exchanges);
                })
                .toList();
    }

    @Transactional
    public void deleteRun(UUID runId, String actorEmail, boolean admin) {
        ValidationRun run = requireRunAccess(runId, actorEmail, admin);
        if (!admin && run.isPublished()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Published runs cannot be deleted");
        }
        if (!admin && run.hasPendingReservation() && !isStaleReservation(run.getPublication())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Run publication is currently in progress");
        }
        if (publicationRepository != null && (run.getPublication() != null || publicationRepository.existsById(runId))) {
            if (run.getPublication() != null) {
                publicationRepository.delete(run.getPublication());
            } else {
                publicationRepository.deleteById(runId);
            }
            run.setPublication(null);
        }
        runRepository.deleteById(runId);
    }

    public long countOwnedPublications(String actorEmail) {
        if (actorEmail == null || publicationRepository == null) {
            return 0;
        }
        return publicationRepository.countOwnedPublications(actorEmail);
    }

    public List<ValidationRunPublication> listPublishedRuns(String actorEmail, boolean admin) {
        if (publicationRepository == null) {
            return List.of();
        }
        Sort sort = Sort.by(Sort.Direction.DESC, "publishedAt");
        List<ValidationRunPublication> raw = admin
                ? publicationRepository.findAll(sort)
                : publicationRepository.findOwnedPublications(actorEmail, sort);
        return raw.stream()
                .filter(p -> !p.isPendingReservation())
                .toList();
    }

    public static final String PENDING_RESERVATION_PR_URL = ValidationRunPublication.PENDING_RESERVATION_PR_URL;

    @EventListener(ApplicationReadyEvent.class)
    @Scheduled(fixedDelayString = "${app.compliance.reservation-cleanup-interval-ms:60000}")
    @Transactional
    public void cleanupStalePendingReservations() {
        try {
            int purged = purgeStalePendingReservations();
            if (purged > 0) {
                log.info("Purged {} stale pending compliance publication reservation(s)", purged);
            }
        } catch (Exception ex) {
            log.debug("Could not purge stale pending compliance publication reservations: {}", ex.getMessage());
        }
    }

    @Transactional
    public int purgeStalePendingReservations() {
        if (publicationRepository == null) {
            return 0;
        }
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minus(getReservationTimeout());
        List<ValidationRunPublication> staleList = publicationRepository.findStalePendingReservations(
                PENDING_RESERVATION_PR_URL, cutoff);
        if (staleList == null || staleList.isEmpty()) {
            return 0;
        }
        int purged = 0;
        for (ValidationRunPublication stale : staleList) {
            UUID runId = stale.getRunId();
            if (runId == null) {
                continue;
            }
            int deleted = publicationRepository.deleteStalePendingReservationById(
                    runId, PENDING_RESERVATION_PR_URL, cutoff);
            if (deleted > 0) {
                purged += deleted;
                if (runRepository != null) {
                    runRepository.findById(runId).ifPresent(r -> {
                        if (r.hasPendingReservation()) {
                            r.setPublication(null);
                            runRepository.save(r);
                        }
                    });
                }
            }
        }
        publicationRepository.flush();
        return purged;
    }

    private final Object reservationLock = new Object();

    public void validatePublishQuota(String actorEmail) {
        validatePublishQuota(actorEmail, null);
    }

    public void validatePublishQuota(String actorEmail, UUID excludeRunId) {
        long currentPublishedCount = countOwnedPublications(actorEmail);
        long activePendingCount = countActivePendingReservations(actorEmail, excludeRunId);
        if (currentPublishedCount + activePendingCount >= maxPublishedRunsPerUser) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "User has reached maximum published compliance runs cap (" + maxPublishedRunsPerUser + ").");
        }
    }

    private long countActivePendingReservations(String actorEmail, UUID excludeRunId) {
        if (publicationRepository == null || actorEmail == null || actorEmail.isBlank()) {
            return 0;
        }
        List<ValidationRunPublication> allForUser = publicationRepository
                .findByCreatedByEmailOrderByPublishedAtDesc(actorEmail);
        if (allForUser == null) {
            return 0;
        }
        long count = 0;
        for (ValidationRunPublication p : allForUser) {
            if (excludeRunId != null && excludeRunId.equals(p.getRunId())) {
                continue;
            }
            if (p.isPendingReservation() && !isStaleReservation(p)) {
                count++;
            }
        }
        return count;
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail) {
        validateProductSlugOwnership(productSlug, ownerEmail, null);
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail, UUID currentRunId) {
        if (productSlug != null && Slugifier.isUuidFormatted(productSlug)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Product slug '" + productSlug + "' cannot use a UUID format reserved for run badge identifiers.");
        }
        if (publicationRepository == null || productSlug == null || productSlug.isBlank()
                || ownerEmail == null || ownerEmail.isBlank()) {
            return;
        }
        List<ValidationRunPublication> existing = publicationRepository
                .findByProductSlugIgnoreCaseOrderByPublishedAtDesc(productSlug);
        if (existing != null) {
            for (ValidationRunPublication p : existing) {
                if (currentRunId != null && currentRunId.equals(p.getRunId())) {
                    continue;
                }
                if (p.isPendingReservation() && isStaleReservation(p)) {
                    continue;
                }
                if (p.getCreatedByEmail() != null && !p.getCreatedByEmail().equalsIgnoreCase(ownerEmail)) {
                    throw new ResponseStatusException(HttpStatus.CONFLICT,
                            "Product slug '" + productSlug + "' is already owned by another publisher.");
                }
            }
        }
    }

    public ValidationRun getRunEntity(UUID runId, String actorEmail, boolean admin) {
        return requireRunAccess(runId, actorEmail, admin);
    }

    public List<ValidationTestResult> getRawTestResults(UUID runId) {
        if (testResultRepository == null) {
            return List.of();
        }
        return testResultRepository.findByRunIdOrderByStartedAtAsc(runId);
    }

    public List<ValidationHttpExchange> getRawExchanges(UUID runId) {
        if (exchangeRepository == null) {
            return List.of();
        }
        List<ValidationHttpExchange> exchanges = exchangeRepository.findServiceProviderConfigExchangesByRunId(runId);
        return exchanges != null ? exchanges : List.of();
    }

    public Optional<ValidationRunPublication> getPublication(UUID runId) {
        if (publicationRepository == null) {
            return Optional.empty();
        }
        return publicationRepository.findById(runId)
                .filter(p -> !p.isPendingReservation());
    }

    @Transactional
    public ValidationRunPublication reservePublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request) {
        synchronized (reservationLock) {
            ValidationRun managedRun = resolveManagedRun(run);
            ValidationRunPublication existing = findExistingPublicationOrReservation(managedRun);

            if (run.isPublished() || managedRun.isPublished()
                    || (existing != null && !existing.isPendingReservation())) {
                throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
            }
            if (existing != null && existing.isPendingReservation() && !isStaleReservation(existing)) {
                throw new IllegalStateException("Validation run publication is already in progress: " + managedRun.getId());
            }

            String ownerEmail = resolveOwnerEmail(managedRun, run, actorEmail);
            validateOwnerQuotaAndSlug(ownerEmail, request.productSlug(), managedRun.getId());

            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            ValidationRunPublication reservation;
            if (existing != null) {
                OffsetDateTime stalePublishedAt = existing.getPublishedAt();
                if (publicationRepository != null) {
                    OffsetDateTime cutoff = now.minus(getReservationTimeout());
                    int claimed = publicationRepository.claimStalePendingReservationById(
                            managedRun.getId(), PENDING_RESERVATION_PR_URL, cutoff, now);
                    if (claimed == 0) {
                        throw new IllegalStateException("Validation run publication is already in progress: " + managedRun.getId());
                    }
                    managedRun = resolveManagedRun(run);
                    existing = findExistingPublicationOrReservation(managedRun);
                }
                log.warn("Reclaiming stale pending publication reservation for runId={} (reserved at {})",
                        managedRun.getId(), stalePublishedAt);
                reservation = existing != null ? existing : new ValidationRunPublication();
                if (existing != null) {
                    reservation.markNotNew();
                }
            } else {
                reservation = new ValidationRunPublication();
            }
            populatePublicationMetadata(reservation, managedRun, ownerEmail, request);
            String baseUrl = getEffectivePublicBaseUrl();
            reservation.setReportUrl(baseUrl + "/compliance/?run=" + managedRun.getId());
            reservation.setBadgeUrl(baseUrl + "/compliance/badges/" + managedRun.getId() + ".svg");
            reservation.setPrUrl(PENDING_RESERVATION_PR_URL);
            reservation.setPublishedAt(now);

            return persistPublicationAndSyncRun(reservation, managedRun, run);
        }
    }

    @Transactional
    public void releasePublicationReservation(ValidationRun run) {
        if (run == null || run.getId() == null) {
            return;
        }
        UUID runId = run.getId();
        if (runRepository != null) {
            runRepository.findById(runId).ifPresent(managedRun -> {
                if (managedRun.hasPendingReservation()) {
                    managedRun.setPublication(null);
                    runRepository.save(managedRun);
                }
            });
        }
        if (publicationRepository != null) {
            publicationRepository.findById(runId).ifPresent(existing -> {
                if (existing.isPendingReservation()) {
                    publicationRepository.deleteById(runId);
                }
            });
        }
        if (run.hasPendingReservation()) {
            run.setPublication(null);
        }
    }

    @Transactional
    public ValidationRunPublication recordPublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result) {
        ValidationRun managedRun = resolveManagedRun(run);
        ValidationRunPublication existing = findExistingPublicationOrReservation(managedRun);

        if (existing != null && existing.isPendingReservation()) {
            existing.markNotNew();
            existing.setReportUrl(result.reportUrl());
            existing.setBadgeUrl(result.badgeUrl());
            existing.setPrUrl(result.prUrl());
            existing.setPublishedAt(result.publishedAt() != null ? result.publishedAt() : OffsetDateTime.now(ZoneOffset.UTC));
            return persistPublicationAndSyncRun(existing, managedRun, run);
        }

        if (run.isPublished() || managedRun.isPublished() || existing != null) {
            throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
        }
        String ownerEmail = resolveOwnerEmail(managedRun, run, actorEmail);
        validateOwnerQuotaAndSlug(ownerEmail, request.productSlug(), managedRun.getId());

        ValidationRunPublication publication = new ValidationRunPublication();
        populatePublicationMetadata(publication, managedRun, ownerEmail, request);
        publication.setReportUrl(result.reportUrl());
        publication.setBadgeUrl(result.badgeUrl());
        publication.setPrUrl(result.prUrl());
        publication.setPublishedAt(result.publishedAt() != null ? result.publishedAt() : OffsetDateTime.now(ZoneOffset.UTC));

        return persistPublicationAndSyncRun(publication, managedRun, run);
    }

    private ValidationRun resolveManagedRun(ValidationRun run) {
        return (runRepository != null && run.getId() != null)
                ? runRepository.findById(run.getId()).orElse(run)
                : run;
    }

    private ValidationRunPublication findExistingPublicationOrReservation(ValidationRun managedRun) {
        if (publicationRepository != null && managedRun.getId() != null) {
            return publicationRepository.findById(managedRun.getId()).orElse(null);
        }
        return managedRun.getPublication();
    }

    private String resolveOwnerEmail(ValidationRun managedRun, ValidationRun detachedRun, String actorEmail) {
        if (managedRun.getCreatedByEmail() != null && !managedRun.getCreatedByEmail().isBlank()) {
            return managedRun.getCreatedByEmail();
        }
        if (detachedRun.getCreatedByEmail() != null && !detachedRun.getCreatedByEmail().isBlank()) {
            return detachedRun.getCreatedByEmail();
        }
        return actorEmail;
    }

    private void validateOwnerQuotaAndSlug(String ownerEmail, String productSlug, UUID runId) {
        validatePublishQuota(ownerEmail, runId);
        validateProductSlugOwnership(productSlug, ownerEmail, runId);
    }

    private void populatePublicationMetadata(
            ValidationRunPublication target,
            ValidationRun managedRun,
            String ownerEmail,
            CompliancePublishRequest request) {
        target.setRun(managedRun);
        target.setCreatedByEmail(ownerEmail);
        target.setProductName(request.productName());
        target.setProductSlug(request.productSlug());
        target.setProductVersion(request.productVersion());
        target.setVendorName(request.vendorName());
        target.setProjectUrl(request.projectUrl());
        target.setLicenseType(request.licenseType());
        target.setShowSubmitter(request.showSubmitter());
        target.setCoreScore(request.coreScore());
        target.setSupportedCapabilities(request.supportedCapabilities());
        target.setTotalCapabilities(request.totalCapabilities());
    }

    private ValidationRunPublication persistPublicationAndSyncRun(
            ValidationRunPublication publication,
            ValidationRun managedRun,
            ValidationRun callerRun) {
        managedRun.setPublication(publication);
        if (publicationRepository != null) {
            publication = publicationRepository.save(publication);
        }
        if (runRepository != null) {
            runRepository.save(managedRun);
        }
        if (managedRun != callerRun) {
            callerRun.setPublication(publication);
        }
        return publication;
    }

    private ValidationRun requireRunAccess(UUID runId, String actorEmail, boolean admin) {
        if (admin) {
            return runRepository.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));
        }
        return runRepository.findAccessibleById(runId, actorEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Test suite not found"));
    }

    int discoverTestCount() {
        return discoverTestCount(null, null);
    }

    int discoverTestCount(String baseUrl, String authToken) {
        try {
            if (baseUrl != null && !baseUrl.isBlank()) {
                ValidatorConfiguration.useRunOverrides(baseUrl, authToken);
            }
            Launcher launcher = LauncherFactory.create();
            LauncherDiscoveryRequest request = buildRequest();
            TestPlan plan = launcher.discover(request);
            long count = plan.countTestIdentifiers(TestIdentifier::isTest);
            return count > 0 ? (int) count : 250;
        } catch (Throwable ex) {
            log.warn("Could not discover test plan count", ex);
            return 250;
        } finally {
            ValidatorConfiguration.clearRunOverrides();
        }
    }

    private static LauncherDiscoveryRequest buildRequest() throws ClassNotFoundException {
        LauncherDiscoveryRequestBuilder builder = LauncherDiscoveryRequestBuilder.request()
                .configurationParameter("junit.jupiter.execution.parallel.enabled", "false");

        for (String className : SpecCatalogService.discoverValidatorSpecClassNames()) {
            Class<?> specClass = Class.forName(className);
            builder.selectors(selectClass(specClass));
        }

        return builder.build();
    }

    void executeLauncher(Launcher launcher, LauncherDiscoveryRequest request, TestExecutionListener listener) {
        launcher.registerTestExecutionListeners(listener);
        launcher.execute(request);
    }

    static class ValidationExecutionListener implements TestExecutionListener {

        private final ValidationRun run;
        private final int plannedTotal;
        private final ValidationProgressTracker progressTracker;
        private final ValidationTestResultRepository testResultRepository;
        private final ValidationHttpExchangeRepository exchangeRepository;
        private final Map<String, OffsetDateTime> starts = new LinkedHashMap<>();

        private int total;
        private int passed;
        private int failed;

        ValidationExecutionListener(ValidationRun run,
                int plannedTotal,
                ValidationProgressTracker progressTracker,
                ValidationTestResultRepository testResultRepository,
                ValidationHttpExchangeRepository exchangeRepository) {
            this.run = run;
            this.plannedTotal = plannedTotal;
            this.progressTracker = progressTracker;
            this.testResultRepository = testResultRepository;
            this.exchangeRepository = exchangeRepository;
        }

        int getTotal() {
            return total;
        }

        int getPassed() {
            return passed;
        }

        int getFailed() {
            return failed;
        }

        @Override
        public void executionStarted(TestIdentifier testIdentifier) {
            if (!testIdentifier.isTest()) {
                return;
            }
            String uniqueId = testIdentifier.getUniqueId();
            starts.put(uniqueId, OffsetDateTime.now());
            ScimRunContext.beginTest(uniqueId);

            int currentTestIndex = total + 1;
            int effectiveTotal = Math.max(plannedTotal, currentTestIndex);
            String displayName = testIdentifier.getDisplayName();
            String specName = resolveSpecName(testIdentifier);

            if (progressTracker != null && run.getId() != null) {
                progressTracker.updateProgress(
                        run.getId(),
                        currentTestIndex,
                        effectiveTotal,
                        passed,
                        failed,
                        specName,
                        displayName
                );
            }
        }

        @Override
        public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult testExecutionResult) {
            if (!testIdentifier.isTest()) {
                return;
            }

            String uniqueId = testIdentifier.getUniqueId();
            OffsetDateTime startedAt = starts.getOrDefault(uniqueId, OffsetDateTime.now());
            OffsetDateTime finishedAt = OffsetDateTime.now();

            ValidationTestResult testResult = new ValidationTestResult();
            testResult.setRun(run);
            testResult.setTestIdentifier(uniqueId);
            testResult.setDisplayName(testIdentifier.getDisplayName());
            testResult.setStatus(normalizeStatus(testExecutionResult.getStatus()));
            testResult.setStartedAt(startedAt);
            testResult.setFinishedAt(finishedAt);

            Object source = testIdentifier.getSource().orElse(null);
            if (source instanceof MethodSource methodSource) {
                testResult.setClassName(methodSource.getClassName());
                testResult.setTestName(methodSource.getMethodName());
            }

            Throwable throwable = testExecutionResult.getThrowable().orElse(null);
            if (throwable != null) {
                testResult.setErrorMessage(throwable.getMessage());
                testResult.setStackTrace(stackTrace(throwable));
            }

            testResult = testResultRepository.save(testResult);

            List<ScimHttpExchange> exchanges = ScimRunContext.getForTest(uniqueId);
            List<ValidationHttpExchange> persisted = new ArrayList<>();
            for (int i = 0; i < exchanges.size(); i++) {
                ScimHttpExchange captured = exchanges.get(i);
                ValidationHttpExchange exchange = new ValidationHttpExchange();
                exchange.setRun(run);
                exchange.setTestResult(testResult);
                exchange.setSequenceNumber(i + 1);
                exchange.setMethod(captured.getMethod());
                exchange.setUrl(captured.getUrl());
                exchange.setRequestHeaders(captured.getRequestHeaders());
                exchange.setRequestBody(captured.getRequestBody());
                exchange.setResponseStatus(captured.getResponseStatus());
                exchange.setResponseHeaders(captured.getResponseHeaders());
                exchange.setResponseBody(captured.getResponseBody());
                exchange.setCreatedAt(captured.getCreatedAt() == null ? OffsetDateTime.now() : captured.getCreatedAt());
                persisted.add(exchange);
            }
            exchangeRepository.saveAll(persisted);

            total++;
            if ("SUCCESS".equals(testResult.getStatus())) {
                passed++;
            } else if (!"ABORTED".equals(testResult.getStatus())) {
                failed++;
            }
            ScimRunContext.endTest();

            int effectiveTotal = Math.max(plannedTotal, total);
            String displayName = testIdentifier.getDisplayName();
            String specName = resolveSpecName(testIdentifier);

            if (progressTracker != null && run.getId() != null) {
                progressTracker.updateProgress(
                        run.getId(),
                        total,
                        effectiveTotal,
                        passed,
                        failed,
                        specName,
                        displayName
                );
            }
        }

        private static String resolveSpecName(TestIdentifier testIdentifier) {
            Object source = testIdentifier.getSource().orElse(null);
            if (source instanceof MethodSource methodSource) {
                String fullClassName = methodSource.getClassName();
                int dot = fullClassName.lastIndexOf('.');
                return dot >= 0 ? fullClassName.substring(dot + 1) : fullClassName;
            }
            return "";
        }

        private static String normalizeStatus(TestExecutionResult.Status status) {
            return switch (status) {
                case SUCCESSFUL -> "SUCCESS";
                case ABORTED -> "ABORTED";
                case FAILED -> "FAILED";
            };
        }

        private static String stackTrace(Throwable throwable) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            throwable.printStackTrace(printWriter);
            return stringWriter.toString();
        }
    }
}
