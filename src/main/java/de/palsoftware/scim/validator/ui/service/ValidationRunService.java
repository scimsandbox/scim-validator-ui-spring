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
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.io.PrintWriter;
import java.io.StringWriter;
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

    public int getMaxRunsPerUser() {
        return maxRunsPerUser;
    }

    public int getMaxPublishedRunsPerUser() {
        return maxPublishedRunsPerUser;
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
                .map(ValidationRunView::from)
                .toList();
    }

    public ValidationRunView getRun(UUID runId, String actorEmail, boolean admin) {
        ValidationRun run = requireRunAccess(runId, actorEmail, admin);
        return ValidationRunView.from(run);
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
        if (run.isPublished() && publicationRepository != null) {
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
        if (admin) {
            return publicationRepository.findAll(sort);
        }
        return publicationRepository.findOwnedPublications(actorEmail, sort);
    }

    public static final String PENDING_RESERVATION_PR_URL = "PENDING_RESERVATION";

    public void validatePublishQuota(String actorEmail) {
        long currentPublishedCount = countOwnedPublications(actorEmail);
        if (currentPublishedCount >= maxPublishedRunsPerUser) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "User has reached maximum published compliance runs cap (" + maxPublishedRunsPerUser + ").");
        }
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail) {
        validateProductSlugOwnership(productSlug, ownerEmail, null);
    }

    public void validateProductSlugOwnership(String productSlug, String ownerEmail, UUID currentRunId) {
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
        return publicationRepository.findById(runId);
    }

    @Transactional
    public ValidationRunPublication reservePublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request) {
        ValidationRun managedRun = (runRepository != null && run.getId() != null)
                ? runRepository.findById(run.getId()).orElse(run)
                : run;
        if (run.isPublished()
                || managedRun.isPublished()
                || (publicationRepository != null && managedRun.getId() != null && publicationRepository.existsById(managedRun.getId()))) {
            throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
        }
        String ownerEmail = (managedRun.getCreatedByEmail() != null && !managedRun.getCreatedByEmail().isBlank())
                ? managedRun.getCreatedByEmail()
                : ((run.getCreatedByEmail() != null && !run.getCreatedByEmail().isBlank()) ? run.getCreatedByEmail() : actorEmail);
        validatePublishQuota(ownerEmail);
        validateProductSlugOwnership(request.productSlug(), ownerEmail, managedRun.getId());

        ValidationRunPublication reservation = new ValidationRunPublication();
        reservation.setRun(managedRun);
        reservation.setCreatedByEmail(ownerEmail);
        reservation.setProductName(request.productName());
        reservation.setProductSlug(request.productSlug());
        reservation.setProductVersion(request.productVersion());
        reservation.setVendorName(request.vendorName());
        reservation.setProjectUrl(request.projectUrl());
        reservation.setLicenseType(request.licenseType());
        reservation.setShowSubmitter(request.showSubmitter());
        reservation.setCoreScore(request.coreScore());
        reservation.setSupportedCapabilities(request.supportedCapabilities());
        reservation.setTotalCapabilities(request.totalCapabilities());
        reservation.setReportUrl("https://scimsandbox.net/compliance/?run=" + managedRun.getId());
        reservation.setBadgeUrl("https://scimsandbox.net/compliance/badges/" + managedRun.getId() + ".svg");
        reservation.setPrUrl(PENDING_RESERVATION_PR_URL);
        reservation.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));

        managedRun.setPublication(reservation);
        if (publicationRepository != null) {
            reservation = publicationRepository.save(reservation);
        }
        if (runRepository != null) {
            runRepository.save(managedRun);
        }
        if (managedRun != run) {
            run.setPublication(reservation);
        }
        return reservation;
    }

    @Transactional
    public void releasePublicationReservation(ValidationRun run) {
        if (run == null || run.getId() == null) {
            return;
        }
        UUID runId = run.getId();
        if (runRepository != null) {
            runRepository.findById(runId).ifPresent(managedRun -> {
                if (managedRun.getPublication() != null
                        && PENDING_RESERVATION_PR_URL.equals(managedRun.getPublication().getPrUrl())) {
                    managedRun.setPublication(null);
                    runRepository.save(managedRun);
                }
            });
        }
        if (publicationRepository != null) {
            publicationRepository.findById(runId).ifPresent(existing -> {
                if (PENDING_RESERVATION_PR_URL.equals(existing.getPrUrl())) {
                    publicationRepository.deleteById(runId);
                }
            });
        }
        if (run.getPublication() != null && PENDING_RESERVATION_PR_URL.equals(run.getPublication().getPrUrl())) {
            run.setPublication(null);
        }
    }

    @Transactional
    public ValidationRunPublication recordPublication(
            ValidationRun run,
            String actorEmail,
            CompliancePublishRequest request,
            CompliancePublicationResult result) {
        ValidationRun managedRun = (runRepository != null && run.getId() != null)
                ? runRepository.findById(run.getId()).orElse(run)
                : run;

        ValidationRunPublication existingReservation = null;
        if (publicationRepository != null && managedRun.getId() != null) {
            ValidationRunPublication found = publicationRepository.findById(managedRun.getId()).orElse(null);
            if (found != null && PENDING_RESERVATION_PR_URL.equals(found.getPrUrl())) {
                existingReservation = found;
            }
        } else if (managedRun.getPublication() != null
                && PENDING_RESERVATION_PR_URL.equals(managedRun.getPublication().getPrUrl())) {
            existingReservation = managedRun.getPublication();
        }

        if (existingReservation != null) {
            existingReservation.setReportUrl(result.reportUrl());
            existingReservation.setBadgeUrl(result.badgeUrl());
            existingReservation.setPrUrl(result.prUrl());
            existingReservation.setPublishedAt(result.publishedAt() != null ? result.publishedAt() : OffsetDateTime.now(ZoneOffset.UTC));
            managedRun.setPublication(existingReservation);
            if (publicationRepository != null) {
                existingReservation = publicationRepository.save(existingReservation);
            }
            if (runRepository != null) {
                runRepository.save(managedRun);
            }
            if (managedRun != run) {
                run.setPublication(existingReservation);
            }
            return existingReservation;
        }

        if (run.isPublished()
                || managedRun.isPublished()
                || (publicationRepository != null && managedRun.getId() != null && publicationRepository.existsById(managedRun.getId()))) {
            throw new IllegalStateException("Validation run has already been published: " + managedRun.getId());
        }
        String ownerEmail = (managedRun.getCreatedByEmail() != null && !managedRun.getCreatedByEmail().isBlank())
                ? managedRun.getCreatedByEmail()
                : ((run.getCreatedByEmail() != null && !run.getCreatedByEmail().isBlank()) ? run.getCreatedByEmail() : actorEmail);
        validatePublishQuota(ownerEmail);
        validateProductSlugOwnership(request.productSlug(), ownerEmail, managedRun.getId());

        ValidationRunPublication publication = new ValidationRunPublication();
        publication.setRun(managedRun);
        publication.setCreatedByEmail(ownerEmail);
        publication.setProductName(request.productName());
        publication.setProductSlug(request.productSlug());
        publication.setProductVersion(request.productVersion());
        publication.setVendorName(request.vendorName());
        publication.setProjectUrl(request.projectUrl());
        publication.setLicenseType(request.licenseType());
        publication.setShowSubmitter(request.showSubmitter());
        publication.setCoreScore(request.coreScore());
        publication.setSupportedCapabilities(request.supportedCapabilities());
        publication.setTotalCapabilities(request.totalCapabilities());
        publication.setReportUrl(result.reportUrl());
        publication.setBadgeUrl(result.badgeUrl());
        publication.setPrUrl(result.prUrl());
        publication.setPublishedAt(result.publishedAt() != null ? result.publishedAt() : OffsetDateTime.now(ZoneOffset.UTC));

        managedRun.setPublication(publication);
        if (publicationRepository != null) {
            publication = publicationRepository.save(publication);
        }
        if (runRepository != null) {
            runRepository.save(managedRun);
        }
        if (managedRun != run) {
            run.setPublication(publication);
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
