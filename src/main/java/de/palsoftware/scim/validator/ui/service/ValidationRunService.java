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
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

@Service
@Transactional(readOnly = true)
public class ValidationRunService {

    private static final Logger log = LoggerFactory.getLogger(ValidationRunService.class);

    private static final List<String> SPEC_CLASS_NAMES = List.of(
            "de.palsoftware.scim.validator.specs.A1_ServiceDiscoverySpec",
            "de.palsoftware.scim.validator.specs.A2_SchemaValidationSpec",
            "de.palsoftware.scim.validator.specs.A3_UserCrudSpec",
            "de.palsoftware.scim.validator.specs.A4_PatchOperationsSpec",
            "de.palsoftware.scim.validator.specs.A5_FilteringSpec",
            "de.palsoftware.scim.validator.specs.A5_PaginationSpec",
            "de.palsoftware.scim.validator.specs.A5_SortingSpec",
            "de.palsoftware.scim.validator.specs.A6_GroupLifecycleSpec",
            "de.palsoftware.scim.validator.specs.A7_BulkOperationsSpec",
            "de.palsoftware.scim.validator.specs.A8_SecurityAndRobustnessSpec",
            "de.palsoftware.scim.validator.specs.A9_NegativeAndEdgeCasesSpec");

    private final ValidationRunRepository runRepository;
    private final ValidationMgmtUserRepository mgmtUserRepository;
    private final ValidationTestResultRepository testResultRepository;
    private final ValidationHttpExchangeRepository exchangeRepository;

    public ValidationRunService(ValidationRunRepository runRepository,
            ValidationMgmtUserRepository mgmtUserRepository,
            ValidationTestResultRepository testResultRepository,
            ValidationHttpExchangeRepository exchangeRepository) {
        this.runRepository = runRepository;
        this.mgmtUserRepository = mgmtUserRepository;
        this.testResultRepository = testResultRepository;
        this.exchangeRepository = exchangeRepository;
    }

    @Value("${app.runs.max-per-user}")
    private int maxRunsPerUser;

    public int getMaxRunsPerUser() {
        return maxRunsPerUser;
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

    @Transactional
    public ExecutionResult executeRun(ValidationRunForm form, String actorEmail) {
        List<ValidationRun> userRuns = runRepository.findOwnedRuns(actorEmail, Sort.by(Sort.Direction.ASC, "executedAt"));
        boolean oldRunDeleted = false;
        
        if (userRuns.size() >= maxRunsPerUser) {
            int toDelete = userRuns.size() - maxRunsPerUser + 1;
            for (int i = 0; i < toDelete; i++) {
                runRepository.delete(userRuns.get(i));
                oldRunDeleted = true;
            }
        }

        ValidationRun run = new ValidationRun();
        run.setName(form.name().trim());
        run.setTargetUrl(form.baseUrl().trim());
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("RUNNING");
        ValidationMgmtUser owner = mgmtUserRepository.findById(actorEmail)
                .orElseThrow(() -> new IllegalStateException("Authenticated management user must exist"));
        run.setCreatedByUser(owner);
        run.setTotalTests(0);
        run.setPassedTests(0);
        run.setFailedTests(0);
        run = runRepository.save(run);

        try {
            ValidatorConfiguration.useRunOverrides(form.baseUrl(), form.authToken());
            ScimBaseSpec.resetRunState();
            ScimRunContext.beginRun(run.getId().toString());

            ValidationExecutionListener listener = new ValidationExecutionListener(run, testResultRepository,
                    exchangeRepository);
            Launcher launcher = LauncherFactory.create();
            launcher.registerTestExecutionListeners(listener);
            launcher.execute(buildRequest());

            run.setTotalTests(listener.total);
            run.setPassedTests(listener.passed);
            run.setFailedTests(listener.failed);
            run.setStatus(listener.failed > 0 ? "FAILED" : "PASSED");
        } catch (Exception ex) {
            log.error("Error executing validation run", ex);
            run.setStatus("ERROR");
        } finally {
            ScimRunContext.endRun();
            ScimBaseSpec.resetRunState();
            ValidatorConfiguration.clearRunOverrides();
        }

        return new ExecutionResult(runRepository.save(run), oldRunDeleted, maxRunsPerUser);
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
        requireRunAccess(runId, actorEmail, admin);
        runRepository.deleteById(runId);
    }

    private ValidationRun requireRunAccess(UUID runId, String actorEmail, boolean admin) {
        if (admin) {
            return runRepository.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Validation run not found"));
        }
        return runRepository.findAccessibleById(runId, actorEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Validation run not found"));
    }

    private static LauncherDiscoveryRequest buildRequest() throws ClassNotFoundException {
        LauncherDiscoveryRequestBuilder builder = LauncherDiscoveryRequestBuilder.request()
                .configurationParameter("junit.jupiter.execution.parallel.enabled", "false");

        for (String className : SPEC_CLASS_NAMES) {
            Class<?> specClass = Class.forName(className);
            builder.selectors(selectClass(specClass));
        }

        return builder.build();
    }

    private static class ValidationExecutionListener implements TestExecutionListener {

        private final ValidationRun run;
        private final ValidationTestResultRepository testResultRepository;
        private final ValidationHttpExchangeRepository exchangeRepository;
        private final Map<String, OffsetDateTime> starts = new LinkedHashMap<>();

        private int total;
        private int passed;
        private int failed;

        private ValidationExecutionListener(ValidationRun run,
                ValidationTestResultRepository testResultRepository,
                ValidationHttpExchangeRepository exchangeRepository) {
            this.run = run;
            this.testResultRepository = testResultRepository;
            this.exchangeRepository = exchangeRepository;
        }

        @Override
        public void executionStarted(TestIdentifier testIdentifier) {
            if (!testIdentifier.isTest()) {
                return;
            }
            String uniqueId = testIdentifier.getUniqueId();
            starts.put(uniqueId, OffsetDateTime.now());
            ScimRunContext.beginTest(uniqueId);
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
            } else {
                failed++;
            }
            ScimRunContext.endTest();
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
