package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.engine.TestDescriptor;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestIdentifier;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Sort;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidationRunServiceTest {

    private static final String BASE_URL_PROPERTY = "scim.baseUrl";
    private static final String AUTH_TOKEN_PROPERTY = "scim.authToken";
    private static final String TESTCONTAINERS_ENABLED_PROPERTY = "SCIM_TESTCONTAINERS_ENABLED";

    @Mock
    private ValidationRunRepository runRepository;

    @Mock
    private ValidationMgmtUserRepository mgmtUserRepository;

    @Mock
    private ValidationTestResultRepository testResultRepository;

    @Mock
    private ValidationHttpExchangeRepository exchangeRepository;

    @Mock
    private ValidationProgressTracker progressTracker;

    @InjectMocks
    private ValidationRunService service;

    private ValidationRun sampleRun;
    private final UUID runId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        sampleRun = new ValidationRun();
        sampleRun.setName("Test Run");
        sampleRun.setTargetUrl("http://example.com/scim");
        sampleRun.setExecutedAt(OffsetDateTime.now());
        sampleRun.setStatus("PASSED");
        sampleRun.setCreatedByUser(new ValidationMgmtUser("user@example.com", OffsetDateTime.now()));
        sampleRun.setTotalTests(10);
        sampleRun.setPassedTests(10);
        sampleRun.setFailedTests(0);

        try {
            var idField = ValidationRun.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(sampleRun, runId);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── buildRequest ───────────────────────────────────────────────────

    @Test
    void buildRequestLoadsValidatorSpecsFromRuntimeClasspath() throws Exception {
        String previousBaseUrl = System.getProperty(BASE_URL_PROPERTY);
        String previousAuthToken = System.getProperty(AUTH_TOKEN_PROPERTY);
        String previousTestcontainersEnabled = System.getProperty(TESTCONTAINERS_ENABLED_PROPERTY);

        System.setProperty(BASE_URL_PROPERTY, "http://localhost:8080/ws/test/scim/v2");
        System.setProperty(AUTH_TOKEN_PROPERTY, "test-token");
        System.setProperty(TESTCONTAINERS_ENABLED_PROPERTY, "false");

        Method buildRequest = ValidationRunService.class.getDeclaredMethod("buildRequest");
        buildRequest.setAccessible(true);

        try {
            LauncherDiscoveryRequest request = (LauncherDiscoveryRequest) buildRequest.invoke(null);
            assertThat(request).isNotNull();
        } finally {
            restoreProperty(BASE_URL_PROPERTY, previousBaseUrl);
            restoreProperty(AUTH_TOKEN_PROPERTY, previousAuthToken);
            restoreProperty(TESTCONTAINERS_ENABLED_PROPERTY, previousTestcontainersEnabled);
        }
    }

    // ─── listRuns ───────────────────────────────────────────────────────

    @Test
    void listRuns_admin_returnsAllRuns() {
        when(runRepository.findAll(any(Sort.class))).thenReturn(List.of(sampleRun));

        List<ValidationRunView> result = service.listRuns("user@example.com", true);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("Test Run");
        verify(runRepository).findAll(any(Sort.class));
    }

    @Test
    void listRuns_nonAdmin_returnsOwnedRuns() {
        when(runRepository.findOwnedRuns(eq("user@example.com"), any(Sort.class)))
                .thenReturn(List.of(sampleRun));

        List<ValidationRunView> result = service.listRuns("user@example.com", false);

        assertThat(result).hasSize(1);
        verify(runRepository).findOwnedRuns(eq("user@example.com"), any(Sort.class));
    }

    @Test
    void listRuns_empty_returnsEmptyList() {
        when(runRepository.findAll(any(Sort.class))).thenReturn(Collections.emptyList());

        List<ValidationRunView> result = service.listRuns("user@example.com", true);

        assertThat(result).isEmpty();
    }

    @Test
    void countOwnedRuns_returnsCountFromRepo() {
        when(runRepository.countOwnedRuns(eq("user@example.com"))).thenReturn(5L);

        long count = service.countOwnedRuns("user@example.com");

        assertThat(count).isEqualTo(5L);
        verify(runRepository).countOwnedRuns(eq("user@example.com"));
    }

    // ─── getRun ─────────────────────────────────────────────────────────

    @Test
    void getRun_admin_found() {
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

        ValidationRunView result = service.getRun(runId, "user@example.com", true);

        assertThat(result.id()).isEqualTo(runId);
        assertThat(result.name()).isEqualTo("Test Run");
    }

    @Test
    void getRun_admin_notFound_throws() {
        when(runRepository.findById(runId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getRun(runId, "user@example.com", true))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void getRun_nonAdmin_accessible() {
        when(runRepository.findAccessibleById(runId, "user@example.com"))
                .thenReturn(Optional.of(sampleRun));

        ValidationRunView result = service.getRun(runId, "user@example.com", false);

        assertThat(result.id()).isEqualTo(runId);
    }

    @Test
    void getRun_nonAdmin_notAccessible_throws() {
        when(runRepository.findAccessibleById(runId, "user@example.com"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getRun(runId, "user@example.com", false))
                .isInstanceOf(ResponseStatusException.class);
    }

    // ─── getTestResults ─────────────────────────────────────────────────

    @Test
    void getTestResults_returnsResultsWithExchanges() {
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

        ValidationTestResult testResult = new ValidationTestResult();
        testResult.setRun(sampleRun);
        testResult.setTestIdentifier("test-1");
        testResult.setDisplayName("Test 1");
        testResult.setStatus("SUCCESS");
        testResult.setStartedAt(OffsetDateTime.now());
        testResult.setFinishedAt(OffsetDateTime.now());

        try {
            var idField = ValidationTestResult.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(testResult, UUID.randomUUID());
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }

        when(testResultRepository.findByRunIdOrderByStartedAtAsc(runId))
                .thenReturn(List.of(testResult));

        ValidationHttpExchange exchange = new ValidationHttpExchange();
        exchange.setRun(sampleRun);
        exchange.setTestResult(testResult);
        exchange.setSequenceNumber(1);
        exchange.setMethod("GET");
        exchange.setUrl("http://example.com/Users");
        exchange.setResponseStatus(200);
        exchange.setCreatedAt(OffsetDateTime.now());

        try {
            var idField = ValidationHttpExchange.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(exchange, UUID.randomUUID());
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }

        when(exchangeRepository.findByTestResultIdOrderBySequenceNumberAsc(testResult.getId()))
                .thenReturn(List.of(exchange));

        List<ValidationTestResultView> results = service.getTestResults(runId, "user@example.com", true);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).displayName()).isEqualTo("Test 1");
        assertThat(results.get(0).exchanges()).hasSize(1);
        assertThat(results.get(0).exchanges().get(0).method()).isEqualTo("GET");
    }

    @Test
    void getTestResults_noResults_returnsEmptyList() {
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(testResultRepository.findByRunIdOrderByStartedAtAsc(runId))
                .thenReturn(Collections.emptyList());

        List<ValidationTestResultView> results = service.getTestResults(runId, "user@example.com", true);

        assertThat(results).isEmpty();
    }

    // ─── deleteRun ──────────────────────────────────────────────────────

    @Test
    void deleteRun_admin_deletesById() {
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

        service.deleteRun(runId, "user@example.com", true);

        verify(runRepository).deleteById(runId);
    }

    @Test
    void deleteRun_nonAdmin_accessible_deletes() {
        when(runRepository.findAccessibleById(runId, "user@example.com"))
                .thenReturn(Optional.of(sampleRun));

        service.deleteRun(runId, "user@example.com", false);

        verify(runRepository).deleteById(runId);
    }

    @Test
    void deleteRun_nonAdmin_notAccessible_throws() {
        when(runRepository.findAccessibleById(runId, "user@example.com"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteRun(runId, "user@example.com", false))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void deleteRun_publishedRun_rejectsForBothAdminAndNonAdmin() {
        de.palsoftware.scim.validator.ui.model.ValidationRunPublication pub =
                new de.palsoftware.scim.validator.ui.model.ValidationRunPublication();
        pub.setRunId(runId);
        pub.setPrUrl("https://github.com/scimsandbox/scim-website/pull/1");
        sampleRun.setPublication(pub);

        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(runRepository.findAccessibleById(runId, "user@example.com")).thenReturn(Optional.of(sampleRun));

        assertThatThrownBy(() -> service.deleteRun(runId, "admin@example.com", true))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.CONFLICT);
                    assertThat(rse.getReason()).contains("Published compliance runs cannot be deleted");
                });

        assertThatThrownBy(() -> service.deleteRun(runId, "user@example.com", false))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    ResponseStatusException rse = (ResponseStatusException) ex;
                    assertThat(rse.getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.CONFLICT);
                    assertThat(rse.getReason()).contains("Published compliance runs cannot be deleted");
                });

        verify(runRepository, org.mockito.Mockito.never()).deleteById(runId);
    }

    // ─── ValidationExecutionListener ───────────────────────────────────

    @Test
    void validationExecutionListener_treatsAbortedTestsAsSkipped() {
        ValidationRun run = new ValidationRun();
        ValidationRunService.ValidationExecutionListener listener =
                new ValidationRunService.ValidationExecutionListener(run, 3, progressTracker, testResultRepository, exchangeRepository);

        TestDescriptor descriptor = org.mockito.Mockito.mock(TestDescriptor.class);
        when(descriptor.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine"));
        when(descriptor.getType()).thenReturn(TestDescriptor.Type.TEST);
        when(descriptor.getDisplayName()).thenReturn("testFeature");
        TestIdentifier identifier = TestIdentifier.from(descriptor);

        when(testResultRepository.save(any(ValidationTestResult.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // 1. Successful test
        listener.executionFinished(identifier, TestExecutionResult.successful());
        assertThat(listener.getTotal()).isEqualTo(1);
        assertThat(listener.getPassed()).isEqualTo(1);
        assertThat(listener.getFailed()).isZero();
        assertThat(listener.getSkipped()).isZero();
        assertThat(listener.getAborted()).isZero();

        // 2. Aborted test (e.g. capability gating)
        listener.executionFinished(identifier, TestExecutionResult.aborted(new RuntimeException("Capability not supported")));
        assertThat(listener.getTotal()).isEqualTo(2);
        assertThat(listener.getPassed()).isEqualTo(1);
        assertThat(listener.getFailed()).isZero();
        assertThat(listener.getSkipped()).isZero();
        assertThat(listener.getAborted()).isEqualTo(1);

        // 3. Failed test
        listener.executionFinished(identifier, TestExecutionResult.failed(new AssertionError("Expectation failed")));
        assertThat(listener.getTotal()).isEqualTo(3);
        assertThat(listener.getPassed()).isEqualTo(1);
        assertThat(listener.getFailed()).isEqualTo(1);
        assertThat(listener.getSkipped()).isZero();
        assertThat(listener.getAborted()).isEqualTo(1);

        // Verify persisted entities and statuses
        ArgumentCaptor<ValidationTestResult> captor = ArgumentCaptor.forClass(ValidationTestResult.class);
        verify(testResultRepository, times(3)).save(captor.capture());

        List<ValidationTestResult> saved = captor.getAllValues();
        assertThat(saved).hasSize(3);

        assertThat(saved.get(0).getStatus()).isEqualTo("SUCCESS");
        assertThat(saved.get(0).getErrorMessage()).isNull();

        assertThat(saved.get(1).getStatus()).isEqualTo("ABORTED");
        assertThat(saved.get(1).getErrorMessage()).isEqualTo("Capability not supported");

        assertThat(saved.get(2).getStatus()).isEqualTo("FAILED");
        assertThat(saved.get(2).getErrorMessage()).isEqualTo("Expectation failed");
    }

    @Test
    void validationExecutionListener_executionSkipped_recordsSkippedTest() {
        ValidationRun run = new ValidationRun();
        ValidationRunService.ValidationExecutionListener listener =
                new ValidationRunService.ValidationExecutionListener(run, 1, progressTracker, testResultRepository, exchangeRepository);

        TestDescriptor descriptor = org.mockito.Mockito.mock(TestDescriptor.class);
        when(descriptor.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine"));
        when(descriptor.getType()).thenReturn(TestDescriptor.Type.TEST);
        when(descriptor.getDisplayName()).thenReturn("skippedFeature");
        TestIdentifier identifier = TestIdentifier.from(descriptor);

        when(testResultRepository.save(any(ValidationTestResult.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        listener.executionSkipped(identifier, "Feature is disabled via @Disabled");

        assertThat(listener.getTotal()).isEqualTo(1);
        assertThat(listener.getSkipped()).isEqualTo(1);
        assertThat(listener.getPassed()).isZero();
        assertThat(listener.getFailed()).isZero();
        assertThat(listener.getAborted()).isZero();

        ArgumentCaptor<ValidationTestResult> captor = ArgumentCaptor.forClass(ValidationTestResult.class);
        verify(testResultRepository).save(captor.capture());

        ValidationTestResult saved = captor.getValue();
        assertThat(saved.getStatus()).isEqualTo("SKIPPED");
        assertThat(saved.getErrorMessage()).isEqualTo("Feature is disabled via @Disabled");
        assertThat(saved.getDisplayName()).isEqualTo("skippedFeature");
    }

    @Test
    void defaultDiscoveredTestCount_is280() {
        assertThat(ValidationRunService.DEFAULT_DISCOVERED_TEST_COUNT).isEqualTo(280);
    }

    @Test
    void executeRun_whenZeroFailedAndAbortedOrSkippedPresent_setsFinalStatusPartial() {
        ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            if (r.getId() == null) {
                try {
                    var f = ValidationRun.class.getDeclaredField("id");
                    f.setAccessible(true);
                    f.set(r, runId);
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException(e);
                }
            }
            return r;
        });
        when(testResultRepository.save(any(ValidationTestResult.class))).thenAnswer(inv -> inv.getArgument(0));

        ValidationRunService partialRunService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 2;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                TestDescriptor d1 = org.mockito.Mockito.mock(TestDescriptor.class);
                when(d1.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine").append("test", "1"));
                when(d1.getType()).thenReturn(TestDescriptor.Type.TEST);
                when(d1.getDisplayName()).thenReturn("USR_01: Pass");
                TestIdentifier id1 = TestIdentifier.from(d1);

                TestDescriptor d2 = org.mockito.Mockito.mock(TestDescriptor.class);
                when(d2.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine").append("test", "2"));
                when(d2.getType()).thenReturn(TestDescriptor.Type.TEST);
                when(d2.getDisplayName()).thenReturn("BLK_01: Skipped");
                TestIdentifier id2 = TestIdentifier.from(d2);

                listener.executionFinished(id1, TestExecutionResult.successful());
                listener.executionSkipped(id2, "Optional capability not supported");
            }
        };

        de.palsoftware.scim.validator.ui.dto.ValidationRunForm form =
                new de.palsoftware.scim.validator.ui.dto.ValidationRunForm("Partial Run", "https://example.com/scim/v2", "token");
        ValidationRunService.ExecutionResult result = partialRunService.executeRun(form, "user@example.com");

        assertThat(result.getRun().getStatus()).isEqualTo("PARTIAL");
        assertThat(result.getRun().getTotalTests()).isEqualTo(2);
        assertThat(result.getRun().getPassedTests()).isEqualTo(1);
        assertThat(result.getRun().getFailedTests()).isZero();
        assertThat(result.getRun().getSkippedTests()).isEqualTo(1);
        verify(progressTracker).completeRun(runId, "PARTIAL", 2, 1, 0);
    }

    @Test
    void validationRun_derivesTransientSkippedAndAbortedCountsFromTestResultsWhenReloaded() {
        ValidationRun reloadedRun = new ValidationRun();

        ValidationTestResult trPass = new ValidationTestResult();
        trPass.setStatus("SUCCESS");
        ValidationTestResult trSkip1 = new ValidationTestResult();
        trSkip1.setStatus("SKIPPED");
        ValidationTestResult trSkip2 = new ValidationTestResult();
        trSkip2.setStatus("SKIPPED");
        ValidationTestResult trAbort = new ValidationTestResult();
        trAbort.setStatus("ABORTED");

        reloadedRun.getTestResults().addAll(List.of(trPass, trSkip1, trSkip2, trAbort));

        assertThat(reloadedRun.getSkippedTests()).isEqualTo(2);
        assertThat(reloadedRun.getAbortedTests()).isEqualTo(1);
    }

    // ─── helpers ────────────────────────────────────────────────────────

    private static void restoreProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}