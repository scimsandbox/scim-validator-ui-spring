package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.base.ScimHttpExchange;
import de.palsoftware.scim.validator.base.ScimRunContext;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.ColourGradientInfo;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceCatalogEntry;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.repo.ValidationMgmtUserRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationHttpExchangeRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationRunRepository;
import de.palsoftware.scim.validator.ui.repo.ValidationTestResultRepository;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.engine.TestDescriptor;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestIdentifier;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Sort;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
        partialRunService.setTargetUrlPolicy(new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));

        ValidationRunForm form =
                new ValidationRunForm("Partial Run", "https://example.com/scim/v2", "token");
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

    @Test
    void scrubSecrets_redactsRawBearerTokenAndAuthorizationHeadersFromPersistedArtifacts() {
        String rawSecret = "super-secret-scim-bearer-9876543210";
        String input = "Request failed with Authorization: Bearer " + rawSecret
                + " and echoed token=" + rawSecret + " plus Bearer anotherLongBearerToken12345";

        String scrubbed = ValidationRunService.scrubSecrets(input, rawSecret);

        assertThat(scrubbed)
                .doesNotContain(rawSecret)
                .doesNotContain("anotherLongBearerToken12345")
                .contains("[REDACTED]");

        // Short tokens (< 8 chars) must NOT corrupt non-secret JSON fields, while still redacting Authorization headers
        String shortJsonAndHeaders = "Authorization: Bearer test\r\n"
                + "{\"Authorization\":\"Bearer test\",\"userName\":\"test\",\"active\":true}\r\n"
                + "Authorization: Basic x";
        String scrubbedShort = ValidationRunService.scrubSecrets(shortJsonAndHeaders, "test");
        assertThat(scrubbedShort)
                .contains("Authorization: Bearer [REDACTED]")
                .contains("\"Authorization\":\"Bearer [REDACTED]\"")
                .contains("Authorization: Basic [REDACTED]")
                .contains("\"userName\":\"test\"");
    }

    @Test
    void executeRunAsync_whenBoundedExecutorQueueFull_rejectsWith429BeforePruningOrSaving() throws Exception {
        java.util.concurrent.CountDownLatch blockWorker = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ThreadPoolExecutor tinyExecutor = ValidationRunService.createBoundedRunExecutor(1, 1);
        try {
            // Occupy the single worker thread and single queue slot
            tinyExecutor.submit(() -> {
                try {
                    blockWorker.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            tinyExecutor.submit(() -> {});

            ValidationRunService boundedService = new ValidationRunService(
                    runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                    progressTracker, tinyExecutor) {
                @Override
                int discoverTestCount(String baseUrl, String authToken) {
                    throw new AssertionError("discoverTestCount must not be invoked when executor rejects");
                }
            };
            boundedService.setTargetUrlPolicy(new TargetUrlPolicy(
                    false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));
            boundedService.setMaxActiveRunsPerUser(5);

            ValidationRunForm form = new ValidationRunForm("Overflow Run", "https://example.com/scim/v2", "tok");
            assertThatThrownBy(() -> boundedService.executeRunAsync(form, "user@example.com"))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));

            verify(runRepository, org.mockito.Mockito.never()).delete(any(ValidationRun.class));
            verify(runRepository, org.mockito.Mockito.never()).deleteById(any(UUID.class));
            verify(runRepository, org.mockito.Mockito.never()).saveAndFlush(any(ValidationRun.class));
        } finally {
            blockWorker.countDown();
            tinyExecutor.shutdownNow();
        }
    }

    @Test
    void executeRun_whenGlobalConcurrentLimitExceeded_rejectsWith429WithoutPruningOrSaving() throws Exception {
        ValidationMgmtUser owner = new ValidationMgmtUser("user1@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user1@example.com")).thenReturn(Optional.of(owner));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            if (r.getId() == null) {
                var f = ValidationRun.class.getDeclaredField("id");
                f.setAccessible(true);
                f.set(r, runId);
            }
            return r;
        });

        java.util.concurrent.CountDownLatch inFlight = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);

        ValidationRunService syncLimitedService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                inFlight.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        syncLimitedService.setTargetUrlPolicy(new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));
        syncLimitedService.setMaxConcurrentRuns(1);
        syncLimitedService.setMaxActiveRunsPerUser(5);

        java.util.concurrent.ExecutorService callerPool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            ValidationRunForm form1 = new ValidationRunForm("Sync 1", "https://example.com/scim/v2", "tok12345");
            java.util.concurrent.Future<ValidationRunService.ExecutionResult> firstCall =
                    callerPool.submit(() -> syncLimitedService.executeRun(form1, "user1@example.com"));

            assertThat(inFlight.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

            ValidationRunForm form2 = new ValidationRunForm("Sync 2", "https://example.com/scim/v2", "tok12345");
            assertThatThrownBy(() -> syncLimitedService.executeRun(form2, "user2@example.com"))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));

            verify(runRepository, org.mockito.Mockito.never()).delete(any(ValidationRun.class));

            release.countDown();
            assertThat(firstCall.get(3, java.util.concurrent.TimeUnit.SECONDS)).isNotNull();
        } finally {
            release.countDown();
            callerPool.shutdownNow();
            syncLimitedService.shutdownExecutor();
        }
    }

    @Test
    void executeRunAndAsync_resolveDnsOncePerRunAndPinTargetDuringExecution() throws Exception {
        ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            if (r.getId() == null) {
                var f = ValidationRun.class.getDeclaredField("id");
                f.setAccessible(true);
                f.set(r, runId);
            }
            return r;
        });
        when(runRepository.saveAndFlush(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            var f = ValidationRun.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(r, runId);
            return r;
        });
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

        java.util.concurrent.atomic.AtomicInteger dnsLookups = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicReference<TargetUrlPolicy.ResolvedTarget> pinnedInDiscover =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<TargetUrlPolicy.ResolvedTarget> pinnedInExecute =
                new java.util.concurrent.atomic.AtomicReference<>();

        TargetUrlPolicy countingPolicy = new TargetUrlPolicy(false, host -> {
            dnsLookups.incrementAndGet();
            return new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")};
        });

        ValidationRunService pinnedService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                pinnedInDiscover.set(de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport.currentPinnedTarget());
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                pinnedInExecute.set(de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport.currentPinnedTarget());
            }
        };
        pinnedService.setTargetUrlPolicy(countingPolicy);
        try {
            ValidationRunForm form = new ValidationRunForm("Pinned Run", "https://example.com/scim/v2", "tok12345");
            pinnedService.executeRun(form, "user@example.com");

            assertThat(dnsLookups.get()).isEqualTo(1);
            assertThat(pinnedInDiscover.get()).isNotNull();
            assertThat(pinnedInExecute.get()).isSameAs(pinnedInDiscover.get());
            assertThat(de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport.currentPinnedTarget()).isNull();

            // Async path also resolves DNS exactly once across foreground + background worker
            dnsLookups.set(0);
            pinnedInDiscover.set(null);
            pinnedInExecute.set(null);

            ValidationRun asyncSample = sampleRun;
            java.util.concurrent.CountDownLatch bgDone = new java.util.concurrent.CountDownLatch(1);
            ValidationRunService asyncPinnedService = new ValidationRunService(
                    runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
                @Override
                int discoverTestCount(String baseUrl, String authToken) {
                    pinnedInDiscover.set(de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport.currentPinnedTarget());
                    return 1;
                }

                @Override
                void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                     LauncherDiscoveryRequest request,
                                     org.junit.platform.launcher.TestExecutionListener listener) {
                    pinnedInExecute.set(de.palsoftware.scim.validator.ui.security.PinnedTargetHttpSupport.currentPinnedTarget());
                    bgDone.countDown();
                }
            };
            asyncPinnedService.setTargetUrlPolicy(countingPolicy);
            try {
                assertThat(asyncSample).isNotNull();
                asyncPinnedService.executeRunAsync(form, "user@example.com");
                assertThat(bgDone.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                assertThat(dnsLookups.get()).isEqualTo(1);
                assertThat(pinnedInDiscover.get()).isNotNull();
                assertThat(pinnedInExecute.get()).isSameAs(pinnedInDiscover.get());
            } finally {
                asyncPinnedService.shutdownExecutor();
            }
        } finally {
            pinnedService.shutdownExecutor();
        }
    }

    @Test
    void executeRunAsync_whenPerUserActiveLimitExceeded_rejectsWith429UntilCompleted() throws Exception {
        ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
        when(runRepository.saveAndFlush(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            var f = ValidationRun.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(r, runId);
            return r;
        });
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

        java.util.concurrent.CountDownLatch releaseRun = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch startedRun = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ThreadPoolExecutor executor = ValidationRunService.createBoundedRunExecutor(2, 4);
        try {
            ValidationRunService perUserLimitedService = new ValidationRunService(
                    runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                    progressTracker, executor) {
                @Override
                int discoverTestCount(String baseUrl, String authToken) {
                    return 2;
                }

                @Override
                void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                     LauncherDiscoveryRequest request,
                                     org.junit.platform.launcher.TestExecutionListener listener) {
                    startedRun.countDown();
                    try {
                        releaseRun.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            };
            perUserLimitedService.setTargetUrlPolicy(new TargetUrlPolicy(
                    false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));
            perUserLimitedService.setMaxActiveRunsPerUser(1);

            ValidationRunForm form = new ValidationRunForm("Run 1", "https://example.com/scim/v2", "tok");
            perUserLimitedService.executeRunAsync(form, "user@example.com");
            assertThat(startedRun.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> perUserLimitedService.executeRunAsync(form, "USER@example.com"))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));
        } finally {
            releaseRun.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void constructorsSettersShutdownAndScrubSecretsEdgeCasesAreCovered() {
        ValidationRunService fourArg = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository);
        fourArg.shutdownExecutor();

        ValidationRunService autowiredCtor = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                null, null, null, null, null, null, null);
        autowiredCtor.setSpecCatalogService(null);
        autowiredCtor.setTargetUrlPolicy(null);
        autowiredCtor.setMaxActiveRunsPerUser(3);
        autowiredCtor.setMaxConcurrentRuns(2);
        assertThat(autowiredCtor.getMaxActiveRunsPerUser()).isEqualTo(3);
        autowiredCtor.shutdownExecutor();

        java.util.concurrent.ThreadPoolExecutor externalExec = ValidationRunService.createBoundedRunExecutor(1, 1);
        try {
            ValidationRunService nonOwning = new ValidationRunService(
                    runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                    progressTracker, externalExec);
            nonOwning.shutdownExecutor();
            assertThat(externalExec.isShutdown()).isFalse();
        } finally {
            externalExec.shutdownNow();
        }

        assertThat(ValidationRunService.scrubSecrets(null, "tok")).isNull();
        assertThat(ValidationRunService.scrubSecrets("", "tok")).isEmpty();
        assertThat(ValidationRunService.scrubSecrets("plain text", null)).isEqualTo("plain text");
        assertThat(ValidationRunService.scrubSecrets("plain text", "   ")).isEqualTo("plain text");
        assertThat(ValidationRunService.scrubSecrets("leaked padded-secret-123 here", "  padded-secret-123  "))
                .isEqualTo("leaked [REDACTED] here");
    }

    @Test
    void executeRun_passedFailedErrorAndTransactionTemplateBranchesAreCovered() {
        ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            if (r.getId() == null) {
                var f = ValidationRun.class.getDeclaredField("id");
                f.setAccessible(true);
                f.set(r, runId);
            }
            return r;
        });
        when(testResultRepository.save(any(ValidationTestResult.class))).thenAnswer(inv -> inv.getArgument(0));

        org.springframework.transaction.PlatformTransactionManager txManager =
                org.mockito.Mockito.mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(txManager.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());

        TargetUrlPolicy publicPolicy = new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")});

        // 1. PASSED branch + TransactionTemplate branch
        ValidationRunService passedSvc = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                TestDescriptor d = org.mockito.Mockito.mock(TestDescriptor.class);
                when(d.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine").append("test", "pass"));
                when(d.getType()).thenReturn(TestDescriptor.Type.TEST);
                when(d.getDisplayName()).thenReturn("USR_01");
                TestIdentifier id = TestIdentifier.from(d);
                listener.executionStarted(id);
                listener.executionFinished(id, TestExecutionResult.successful());
            }
        };
        passedSvc.setTargetUrlPolicy(publicPolicy);
        passedSvc.setTransactionManager(txManager);
        try {
            ValidationRunForm form = new ValidationRunForm("Pass Run", "https://example.com/scim/v2", "secret-12345");
            assertThat(passedSvc.executeRun(form, "user@example.com").getRun().getStatus()).isEqualTo("PASSED");
        } finally {
            passedSvc.shutdownExecutor();
        }

        // 2. FAILED branch
        ValidationRunService failedSvc = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                TestDescriptor d = org.mockito.Mockito.mock(TestDescriptor.class);
                when(d.getUniqueId()).thenReturn(UniqueId.forEngine("test-engine").append("test", "fail"));
                when(d.getType()).thenReturn(TestDescriptor.Type.TEST);
                when(d.getDisplayName()).thenReturn("USR_02");
                TestIdentifier id = TestIdentifier.from(d);
                listener.executionFinished(id, TestExecutionResult.failed(new AssertionError("Failed with secret-12345")));
            }
        };
        failedSvc.setTargetUrlPolicy(publicPolicy);
        try {
            ValidationRunForm form = new ValidationRunForm("Fail Run", "https://example.com/scim/v2", "secret-12345");
            assertThat(failedSvc.executeRun(form, "user@example.com").getRun().getStatus()).isEqualTo("FAILED");
        } finally {
            failedSvc.shutdownExecutor();
        }

        // 3. ERROR catch branch (launcher throws RuntimeException containing token)
        ValidationRunService errorSvc = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                throw new IllegalStateException("Crash carrying secret-12345");
            }
        };
        errorSvc.setTargetUrlPolicy(publicPolicy);
        try {
            ValidationRunForm form = new ValidationRunForm("Error Run", "https://example.com/scim/v2", "secret-12345");
            assertThat(errorSvc.executeRun(form, "user@example.com").getRun().getStatus()).isEqualTo("ERROR");
            verify(progressTracker).failRun(eq(runId), eq("Crash carrying [REDACTED]"));
        } finally {
            errorSvc.shutdownExecutor();
        }
    }

    @Test
    void executeRunAsync_withActiveTransactionSynchronization_handlesCommitRejectionAndRollback() throws Exception {
        ValidationMgmtUser anonOwner = new ValidationMgmtUser("   ", OffsetDateTime.now());
        when(mgmtUserRepository.findById("   ")).thenReturn(Optional.of(anonOwner));
        when(runRepository.saveAndFlush(any(ValidationRun.class))).thenAnswer(inv -> {
            ValidationRun r = inv.getArgument(0);
            var f = ValidationRun.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(r, runId);
            return r;
        });

        TargetUrlPolicy publicPolicy = new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")});
        ValidationRunForm form = new ValidationRunForm("SyncTx Run", "https://example.com/scim/v2", "secret-xyz");

        // Case A: Transaction synchronization active + shut/full executor rejects BEFORE DB insert or prune
        java.util.concurrent.ThreadPoolExecutor shutExecutor = ValidationRunService.createBoundedRunExecutor(1, 1);
        shutExecutor.shutdownNow();

        ValidationRunService txRejectedService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, shutExecutor) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                throw new AssertionError("discoverTestCount must not run when executor rejects");
            }
        };
        txRejectedService.setTargetUrlPolicy(publicPolicy);
        txRejectedService.setMaxActiveRunsPerUser(1);

        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        try {
            assertThatThrownBy(() -> txRejectedService.executeRunAsync(form, "   "))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));
        } finally {
            org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
        }
        verify(runRepository, org.mockito.Mockito.never()).saveAndFlush(any(ValidationRun.class));

        // Case B: Transaction synchronization active + live executor -> commit hands off task; rollback cancels cleanly
        java.util.concurrent.CountDownLatch committedBgDone = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger launcherRuns = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.ThreadPoolExecutor liveExecutor = ValidationRunService.createBoundedRunExecutor(2, 4);
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> inv.getArgument(0));
        try {
            ValidationRunService txLiveService = new ValidationRunService(
                    runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, liveExecutor) {
                @Override
                int discoverTestCount(String baseUrl, String authToken) {
                    return 3;
                }

                @Override
                void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                     LauncherDiscoveryRequest request,
                                     org.junit.platform.launcher.TestExecutionListener listener) {
                    launcherRuns.incrementAndGet();
                    committedBgDone.countDown();
                }
            };
            txLiveService.setTargetUrlPolicy(publicPolicy);
            txLiveService.setMaxActiveRunsPerUser(1);

            // Rollback first: must release user's single active slot and NOT invoke executeLauncher
            org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
            try {
                txLiveService.executeRunAsync(form, "   ");
                for (org.springframework.transaction.support.TransactionSynchronization sync :
                        org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations()) {
                    sync.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_ROLLED_BACK);
                }
            } finally {
                org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
            }
            assertThat(launcherRuns.get()).isZero();
            verify(progressTracker).removeRun(runId);

            // Commit second (same user, maxActiveRunsPerUser=1 proves rollback released slot): invokes executeLauncher
            org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
            try {
                txLiveService.executeRunAsync(form, "   ");
                for (org.springframework.transaction.support.TransactionSynchronization sync :
                        org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations()) {
                    sync.afterCommit();
                    sync.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_COMMITTED);
                }
            } finally {
                org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
            }
            assertThat(committedBgDone.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            assertThat(launcherRuns.get()).isEqualTo(1);
        } finally {
            liveExecutor.shutdownNow();
        }

        // Case C: runTestsInBackground exception branch scrubs token and marks run ERROR
        ValidationRunService bgErrorService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, shutExecutor) {
            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                throw new RuntimeException("Background failure with secret-xyz");
            }
        };
        bgErrorService.setTargetUrlPolicy(publicPolicy);
        bgErrorService.runTestsInBackground(runId, form, 4);
        assertThat(sampleRun.getStatus()).isEqualTo("ERROR");
        verify(progressTracker).failRun(eq(runId), eq("Background failure with [REDACTED]"));

        // Case D: Background worker interrupted while waiting for global concurrent permit marks run ERROR cleanly
        bgErrorService.setMaxConcurrentRuns(1);
        java.lang.reflect.Method execPermitted = ValidationRunService.class.getDeclaredMethod(
                "executePermittedBackgroundRun",
                UUID.class, ValidationRunForm.class, int.class, TargetUrlPolicy.ResolvedTarget.class, String.class);
        execPermitted.setAccessible(true);
        sampleRun.setStatus("RUNNING");
        Thread.currentThread().interrupt();
        try {
            execPermitted.invoke(bgErrorService, runId, form, 4, publicPolicy.resolve(form.baseUrl()), "user@example.com");
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
        assertThat(sampleRun.getStatus()).isEqualTo("ERROR");
        verify(progressTracker).failRun(eq(runId), eq("Validation run interrupted"));
    }

    // ─── 2 MiB UTF-8 & VARCHAR defensive truncation (Issue #4) ──────────

    @Test
    void truncateUtf8Bytes_and_truncateChars_preserveCodePointAndSurrogateBoundaries() {
        assertThat(ValidationRunService.truncateUtf8Bytes(null, ValidationRunService.MAX_DB_TEXT_BYTES)).isNull();
        assertThat(ValidationRunService.truncateUtf8Bytes("exact", 5)).isEqualTo("exact");
        assertThat(ValidationRunService.truncateUtf8Bytes("overflow", 0)).isEmpty();
        assertThat(ValidationRunService.truncateUtf8Bytes("overflow-small-budget", 5)).isEqualTo("...[t");

        // Exact 2 MiB ASCII stays untouched
        String exact2MiB = "a".repeat(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(ValidationRunService.truncateUtf8Bytes(exact2MiB, ValidationRunService.MAX_DB_TEXT_BYTES))
                .isSameAs(exact2MiB);

        // > 2 MiB ASCII truncates to exact 2,097,152 bytes with '...[truncated]' suffix
        String overAscii = "a".repeat(ValidationRunService.MAX_DB_TEXT_BYTES + 1000);
        String truncatedAscii = ValidationRunService.truncateUtf8Bytes(overAscii, ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(truncatedAscii.getBytes(StandardCharsets.UTF_8)).hasSize(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(truncatedAscii).endsWith("...[truncated]");

        // > 2 MiB misaligned 3-byte UTF-8 ('€' = 3 bytes) and 4-byte UTF-8 ('🚀' = 4 bytes, UTF-16 surrogate pair)
        for (String prefix : List.of("", "x", "xy")) {
            String overEuro = prefix + "€".repeat(750_000);
            String truncatedEuro = ValidationRunService.truncateUtf8Bytes(overEuro, ValidationRunService.MAX_DB_TEXT_BYTES);
            int euroBytes = truncatedEuro.getBytes(StandardCharsets.UTF_8).length;
            assertThat(euroBytes).isBetween(ValidationRunService.MAX_DB_TEXT_BYTES - 3, ValidationRunService.MAX_DB_TEXT_BYTES);
            assertThat(truncatedEuro).endsWith("...[truncated]").doesNotContain("\uFFFD");
        }
        for (String prefix : List.of("", "a", "ab", "abc")) {
            String overRocket = prefix + "🚀".repeat(550_000);
            String truncatedRocket = ValidationRunService.truncateUtf8Bytes(overRocket, ValidationRunService.MAX_DB_TEXT_BYTES);
            int rocketBytes = truncatedRocket.getBytes(StandardCharsets.UTF_8).length;
            assertThat(rocketBytes).isBetween(ValidationRunService.MAX_DB_TEXT_BYTES - 3, ValidationRunService.MAX_DB_TEXT_BYTES);
            assertThat(truncatedRocket).endsWith("...[truncated]").doesNotContain("\uFFFD");
            assertThat(Character.isHighSurrogate(truncatedRocket.charAt(truncatedRocket.length() - 15))).isFalse();
        }

        // truncateChars avoids splitting UTF-16 surrogate pairs at the boundary
        assertThat(ValidationRunService.truncateChars(null, 10)).isNull();
        assertThat(ValidationRunService.truncateChars("abc", 0)).isEmpty();
        assertThat(ValidationRunService.truncateChars("abc", 5)).isEqualTo("abc");
        String surrogateAtBoundary = "a".repeat(9) + "🚀" + "z"; // '🚀' occupies indices 9 (high) and 10 (low)
        String truncatedSurrogate = ValidationRunService.truncateChars(surrogateAtBoundary, 10);
        assertThat(truncatedSurrogate).isEqualTo("a".repeat(9));
    }

    @Test
    @SuppressWarnings("unchecked")
    void validationExecutionListener_boundsOversizedTextAndVarcharColumnsAfterScrubbingSecrets() {
        ValidationRun run = new ValidationRun();
        String secretToken = "tok12345"; // 8 chars -> replaced by 10-char "[REDACTED]"
        ValidationRunService.ValidationExecutionListener listener =
                new ValidationRunService.ValidationExecutionListener(
                        run, 2, progressTracker, testResultRepository, exchangeRepository, secretToken);

        String longClassName = "com.example." + "C".repeat(350);
        String longMethodName = "test" + "M".repeat(350);
        String longDisplayName = "Display " + "D".repeat(550);
        UniqueId longUniqueId = UniqueId.forEngine("test-engine").append("test", "U".repeat(550));

        TestDescriptor descriptor = org.mockito.Mockito.mock(TestDescriptor.class);
        when(descriptor.getUniqueId()).thenReturn(longUniqueId);
        when(descriptor.getType()).thenReturn(TestDescriptor.Type.TEST);
        when(descriptor.getDisplayName()).thenReturn(longDisplayName);
        when(descriptor.getSource()).thenReturn(Optional.of(MethodSource.from(longClassName, longMethodName)));
        TestIdentifier identifier = TestIdentifier.from(descriptor);

        when(testResultRepository.save(any(ValidationTestResult.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String hugeError = secretToken + " " + "€".repeat(750_000);
        RuntimeException hugeException = new RuntimeException(hugeError) {
            @Override
            public void printStackTrace(java.io.PrintWriter s) {
                s.print("Stack leak " + secretToken + " " + "🚀".repeat(550_000));
            }
        };

        ScimRunContext.beginRun("run-oversized");
        try {
            listener.executionStarted(identifier);

            ScimHttpExchange rawExchange = new ScimHttpExchange();
            rawExchange.setMethod("CUSTOM_LONG_METHOD_NAME");
            rawExchange.setUrl("https://scim.example.com/v2/Users?" + "q".repeat(1200));
            rawExchange.setRequestHeaders("X-Leak: " + secretToken + "\n" + "H".repeat(ValidationRunService.MAX_DB_TEXT_BYTES + 500));
            rawExchange.setRequestBody(secretToken + "€".repeat(750_000));
            rawExchange.setResponseStatus(500);
            rawExchange.setResponseHeaders("X-Resp: " + "🚀".repeat(550_000));
            rawExchange.setResponseBody("B".repeat(ValidationRunService.MAX_DB_TEXT_BYTES + 5000));
            ScimRunContext.record(rawExchange);

            listener.executionFinished(identifier, TestExecutionResult.failed(hugeException));

            // Also verify executionSkipped truncates oversized reason and VARCHAR fields
            listener.executionSkipped(identifier, secretToken + " " + "S".repeat(ValidationRunService.MAX_DB_TEXT_BYTES + 500));
        } finally {
            ScimRunContext.endRun();
        }

        ArgumentCaptor<ValidationTestResult> trCaptor = ArgumentCaptor.forClass(ValidationTestResult.class);
        verify(testResultRepository, times(2)).save(trCaptor.capture());

        ValidationTestResult finishedResult = trCaptor.getAllValues().get(0);
        assertThat(finishedResult.getTestIdentifier()).hasSize(500);
        assertThat(finishedResult.getDisplayName()).hasSize(500);
        assertThat(finishedResult.getClassName()).hasSize(300);
        assertThat(finishedResult.getTestName()).hasSize(300);
        assertThat(finishedResult.getErrorMessage())
                .startsWith("[REDACTED]")
                .doesNotContain(secretToken)
                .endsWith("...[truncated]");
        assertThat(finishedResult.getErrorMessage().getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(finishedResult.getStackTrace())
                .contains("[REDACTED]")
                .doesNotContain(secretToken)
                .endsWith("...[truncated]");
        assertThat(finishedResult.getStackTrace().getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);

        ValidationTestResult skippedResult = trCaptor.getAllValues().get(1);
        assertThat(skippedResult.getTestIdentifier()).hasSize(500);
        assertThat(skippedResult.getDisplayName()).hasSize(500);
        assertThat(skippedResult.getClassName()).hasSize(300);
        assertThat(skippedResult.getTestName()).hasSize(300);
        assertThat(skippedResult.getErrorMessage())
                .startsWith("[REDACTED]")
                .doesNotContain(secretToken)
                .endsWith("...[truncated]");
        assertThat(skippedResult.getErrorMessage().getBytes(StandardCharsets.UTF_8).length)
                .isEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);

        ArgumentCaptor<List<ValidationHttpExchange>> exCaptor = ArgumentCaptor.forClass(List.class);
        verify(exchangeRepository).saveAll(exCaptor.capture());
        assertThat(exCaptor.getValue()).hasSize(1);
        ValidationHttpExchange savedEx = exCaptor.getValue().get(0);
        assertThat(savedEx.getMethod()).hasSize(16);
        assertThat(savedEx.getUrl()).hasSize(1000);
        assertThat(savedEx.getRequestHeaders()).doesNotContain(secretToken).endsWith("...[truncated]");
        assertThat(savedEx.getRequestHeaders().getBytes(StandardCharsets.UTF_8).length)
                .isEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(savedEx.getRequestBody()).startsWith("[REDACTED]").doesNotContain(secretToken).endsWith("...[truncated]");
        assertThat(savedEx.getRequestBody().getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(savedEx.getResponseHeaders()).endsWith("...[truncated]");
        assertThat(savedEx.getResponseHeaders().getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);
        assertThat(savedEx.getResponseBody()).endsWith("...[truncated]");
        assertThat(savedEx.getResponseBody().getBytes(StandardCharsets.UTF_8).length)
                .isEqualTo(ValidationRunService.MAX_DB_TEXT_BYTES);
    }

    // ─── Reconciled catalog metadata sanitization (Issue #5) ────────────

    @Test
    void recordPublication_sanitizesMalformedReconciledCatalogEntryAndPrUrl() {
        ValidationRunPublicationRepository pubRepo = org.mockito.Mockito.mock(ValidationRunPublicationRepository.class);
        when(pubRepo.save(any(ValidationRunPublication.class))).thenAnswer(inv -> inv.getArgument(0));
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> inv.getArgument(0));

        ValidationRunService pubService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, pubRepo, progressTracker);
        pubService.setPublicBaseUrl("https://scimsandbox.org");

        CompliancePublishRequest validRequest = new CompliancePublishRequest(
                runId,
                "Validated Product",
                "validated-product",
                "1.0.0",
                "Validated Vendor",
                "https://github.com/acme/validated",
                "Apache-2.0",
                true,
                94,
                "EMERALD",
                9,
                10,
                "user@example.com",
                "https://scim.example.com/v2"
        );

        // Case 1: Active PENDING_RESERVATION + malformed reconciled catalog entry (UUID slug, schemeless projectUrl,
        // oversized/blank strings, out-of-bounds score & capabilities, malformed prUrl/reportUrl/badgeUrl)
        ValidationRunPublication pending = new ValidationRunPublication();
        pending.setRun(sampleRun);
        pending.setCreatedByEmail("user@example.com");
        pending.setProductName("Validated Product");
        pending.setProductSlug("validated-product");
        pending.setProductVersion("1.0.0");
        pending.setLicenseType("Apache-2.0");
        pending.setShowSubmitter(true);
        pending.setCoreScore(94);
        pending.setSupportedCapabilities(9);
        pending.setTotalCapabilities(10);
        pending.setReportUrl("https://scimsandbox.org/compliance/?run=" + runId);
        pending.setBadgeUrl("https://scimsandbox.org/compliance/badges/" + runId + ".svg");
        pending.setPrUrl(ValidationRunService.PENDING_RESERVATION_PR_URL);
        pending.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
        when(pubRepo.findById(runId)).thenReturn(Optional.of(pending));

        ComplianceCatalogEntry malformedEntry = new ComplianceCatalogEntry(
                runId,
                "   ", // blank productName -> fallback
                "11111111-1111-1111-1111-111111111111", // UUID slug -> fallback
                "v".repeat(61), // > 60 chars productVersion -> fallback
                "V".repeat(121), // > 120 chars vendorName -> fallback
                "github.com/schemeless/repo", // malformed projectUrl -> fallback to request.projectUrl()
                "L\nInvalidControl", // control char in licenseType -> fallback
                150, // out-of-range coreScore -> fallback
                ColourGradientInfo.from("EMERALD", 94),
                12, // supported > total -> fallback
                10,
                "compliance/reports/bad path with spaces.json",
                "compliance/badges/validated-product.svg",
                "2026-11-13T10:00:00Z"
        );
        CompliancePublicationResult malformedResult = CompliancePublicationResult.reconciled(
                runId,
                "https://github.com/scimsandbox/scim-website/blob/main/bad path with spaces.json",
                "javascript:alert(1)",
                "https://user:secret@scimsandbox.org/badge.svg",
                "reconciled",
                OffsetDateTime.now(ZoneOffset.UTC),
                malformedEntry
        );

        ValidationRunPublication savedFromPending = pubService.recordPublication(
                sampleRun, "user@example.com", validRequest, malformedResult);

        assertThat(savedFromPending.getProductName()).isEqualTo("Validated Product");
        assertThat(savedFromPending.getProductSlug()).isEqualTo("validated-product");
        assertThat(savedFromPending.getProductVersion()).isEqualTo("1.0.0");
        assertThat(savedFromPending.getVendorName()).isEqualTo("Validated Vendor");
        assertThat(savedFromPending.getProjectUrl()).isEqualTo("https://github.com/acme/validated");
        assertThat(savedFromPending.getLicenseType()).isEqualTo("Apache-2.0");
        assertThat(savedFromPending.isShowSubmitter()).isTrue();
        assertThat(savedFromPending.getCoreScore()).isEqualTo(94);
        assertThat(savedFromPending.getSupportedCapabilities()).isEqualTo(9);
        assertThat(savedFromPending.getTotalCapabilities()).isEqualTo(10);
        assertThat(savedFromPending.getPrUrl()).isNull();
        assertThat(savedFromPending.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(savedFromPending.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");

        // Case 2: No prior reservation + blank reconciled projectUrl clears projectUrl to null,
        // mixed-case trimmed slug normalizes cleanly, and mixed-case HTTPS URLs are accepted
        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());

        ComplianceCatalogEntry blankUrlAndMixedSlugEntry = new ComplianceCatalogEntry(
                runId,
                "  Canonical Name  ",
                "  Canonical-Slug  ",
                "2.0.0",
                "   ", // blank vendor -> null
                "   ", // blank projectUrl -> null (intentional absence in catalog)
                "MIT",
                97,
                ColourGradientInfo.from("EMERALD", 97),
                10,
                10,
                "compliance/reports/canonical-slug/2.0.0.json",
                "compliance/badges/canonical-slug.svg",
                "2026-11-13T11:00:00Z"
        );
        CompliancePublicationResult cleanMixedResult = CompliancePublicationResult.reconciled(
                runId,
                "HTTPS://github.com/scimsandbox/scim-website/pull/99",
                "HTTPS://scimsandbox.org/compliance/?run=" + runId,
                "Http://scimsandbox.org/compliance/badges/" + runId + ".svg",
                "sha99",
                OffsetDateTime.now(ZoneOffset.UTC),
                blankUrlAndMixedSlugEntry
        );

        ValidationRunPublication savedFresh = pubService.recordPublication(
                sampleRun, "user@example.com", validRequest, cleanMixedResult);

        assertThat(savedFresh.getProductName()).isEqualTo("Canonical Name");
        assertThat(savedFresh.getProductSlug()).isEqualTo("canonical-slug");
        assertThat(savedFresh.getProductVersion()).isEqualTo("2.0.0");
        assertThat(savedFresh.getVendorName()).isNull();
        assertThat(savedFresh.getProjectUrl()).isNull();
        assertThat(savedFresh.getLicenseType()).isEqualTo("MIT");
        assertThat(savedFresh.getCoreScore()).isEqualTo(97);
        assertThat(savedFresh.getSupportedCapabilities()).isEqualTo(10);
        assertThat(savedFresh.getTotalCapabilities()).isEqualTo(10);
        assertThat(savedFresh.getPrUrl()).isEqualTo("HTTPS://github.com/scimsandbox/scim-website/pull/99");
        assertThat(savedFresh.getReportUrl()).isEqualTo("HTTPS://scimsandbox.org/compliance/?run=" + runId);
        assertThat(savedFresh.getBadgeUrl()).isEqualTo("Http://scimsandbox.org/compliance/badges/" + runId + ".svg");

        assertThat(ValidationRunService.sanitizePrUrl("PENDING_RESERVATION")).isNull();
        assertThat(ValidationRunService.sanitizePrUrl("   ")).isNull();
        assertThat(ValidationRunService.sanitizePrUrl("https://token@github.com/pr/1")).isNull();
        assertThat(ValidationRunService.isValidPublicationHttpUrl(null)).isFalse();
        assertThat(ValidationRunService.isValidPublicationHttpUrl("HTTPS://github.com/acme/scim")).isTrue();
        assertThat(ValidationRunService.isValidPublicationHttpUrl("https:///empty-host")).isFalse();

        // Fallback URL & null publishedAt branches when publicBaseUrl is blank and no prior fallback URLs exist
        pubService.setPublicBaseUrl("   ");
        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());
        CompliancePublicationResult nullDatesAndUrls = CompliancePublicationResult.reconciled(
                runId, null, null, null, "sha0", null, null);
        ValidationRunPublication savedDefaults = pubService.recordPublication(
                sampleRun, "user@example.com", validRequest, nullDatesAndUrls);
        assertThat(savedDefaults.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(savedDefaults.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");
        assertThat(savedDefaults.getPublishedAt()).isNotNull();
    }

    @Test
    void unicodeWhitespaceAndControlHandling_alignsWithPostgreSql17UrlConstraints() {
        List<String> unicodeSpaces = List.of("\u00A0", "\u2007", "\u202F", "\uFEFF", "\u0085", "\u180E");

        for (String sp : unicodeSpaces) {
            // Internal Unicode spaces/BOM/NEL must be rejected by isValidPublicationHttpUrl, sanitizeOptionalHttpUrl,
            // sanitizePrUrl, and validateAndNormalizeTargetUrl
            String internalPathUrl = "https://github.com/acme" + sp + "scim";
            String internalHostUrl = "https://" + sp + "github.com/acme/scim";
            assertThat(ValidationRunService.isValidPublicationHttpUrl(internalPathUrl))
                    .as("internal %s in path", sp.codePoints().findFirst().orElse(0))
                    .isFalse();
            assertThat(ValidationRunService.isValidPublicationHttpUrl(internalHostUrl))
                    .as("internal %s at host start", sp.codePoints().findFirst().orElse(0))
                    .isFalse();
            assertThat(ValidationRunService.sanitizeOptionalHttpUrl(internalPathUrl)).isNull();
            assertThat(ValidationRunService.sanitizePrUrl(internalPathUrl)).isNull();
            assertThatThrownBy(() -> ValidationRunService.validateAndNormalizeTargetUrl(internalPathUrl))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("whitespace or control");

            // Leading/trailing Unicode spaces/BOM/NEL must be stripped cleanly
            String padded = sp + "https://github.com/acme/scim" + sp;
            assertThat(ValidationRunService.trimUnicodeSpaces(padded)).isEqualTo("https://github.com/acme/scim");
            assertThat(ValidationRunService.sanitizeOptionalHttpUrl(padded)).isEqualTo("https://github.com/acme/scim");
            assertThat(ValidationRunService.sanitizePrUrl(padded)).isEqualTo("https://github.com/acme/scim");
            assertThat(ValidationRunService.validateAndNormalizeTargetUrl(padded)).isEqualTo("https://github.com/acme/scim");

            // Strings consisting only of Unicode spaces/BOM/NEL normalize to null / empty rejection
            assertThat(ValidationRunService.sanitizeOptionalHttpUrl(sp + sp)).isNull();
            assertThat(ValidationRunService.sanitizePrUrl(sp + sp)).isNull();
            assertThatThrownBy(() -> ValidationRunService.validateAndNormalizeTargetUrl(sp + sp))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not be empty");
        }
        assertThat(ValidationRunService.trimUnicodeSpaces(null)).isNull();
        assertThat(ValidationRunService.trimUnicodeSpaces("")).isEmpty();
        assertThat(ValidationRunService.sanitizeOptionalHttpUrl(null)).isNull();
        assertThat(ValidationRunService.sanitizePrUrl(null)).isNull();
        assertThatThrownBy(() -> ValidationRunService.validateAndNormalizeTargetUrl(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");

        // Verify recordPublication handles both NBSP/BOM-padded valid URLs and internal-NBSP malformed URLs
        ValidationRunPublicationRepository pubRepo = org.mockito.Mockito.mock(ValidationRunPublicationRepository.class);
        when(pubRepo.save(any(ValidationRunPublication.class))).thenAnswer(inv -> inv.getArgument(0));
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> inv.getArgument(0));

        ValidationRunService pubService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, pubRepo, progressTracker);
        pubService.setPublicBaseUrl("https://scimsandbox.org");

        CompliancePublishRequest requestWithNbspPadding = new CompliancePublishRequest(
                runId,
                "NBSP Product",
                "nbsp-product",
                "1.0.0",
                "Vendor",
                "\uFEFF\u00A0https://github.com/acme/nbsp-fallback\u202F",
                "MIT",
                false,
                95,
                "EMERALD",
                10,
                10,
                "user@example.com",
                "https://scim.example.com/v2"
        );

        // Internal NBSP/BOM/figure-space in reconciled catalog & result URLs -> rejected with fallback
        ComplianceCatalogEntry internalNbspEntry = new ComplianceCatalogEntry(
                runId,
                "NBSP Product",
                "\u00A0NBSP-Product\u2007",
                "1.0.0",
                "Vendor",
                "https://github.com/acme/\u00A0bad-project",
                "MIT",
                95,
                ColourGradientInfo.from("EMERALD", 95),
                10,
                10,
                "compliance/reports/nbsp-product/1.0.0.json",
                "compliance/badges/nbsp-product.svg",
                "2026-11-14T08:00:00Z"
        );
        CompliancePublicationResult internalNbspResult = CompliancePublicationResult.reconciled(
                runId,
                "https://github.com/scimsandbox/scim-website/pull/\u202F42",
                "https://scimsandbox.org/compliance/?run=\u2007" + runId,
                "https://scimsandbox.org/compliance/badges/\uFEFF" + runId + ".svg",
                "sha-nbsp",
                OffsetDateTime.now(ZoneOffset.UTC),
                internalNbspEntry
        );

        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());
        ValidationRunPublication savedFallback = pubService.recordPublication(
                sampleRun, "user@example.com", requestWithNbspPadding, internalNbspResult);

        assertThat(savedFallback.getProductSlug()).isEqualTo("nbsp-product");
        assertThat(savedFallback.getProjectUrl()).isEqualTo("https://github.com/acme/nbsp-fallback");
        assertThat(savedFallback.getPrUrl()).isNull();
        assertThat(savedFallback.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(savedFallback.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");

        // Leading/trailing NBSP/BOM on reconciled URLs -> stripped cleanly, and NBSP-only projectUrl clears to null
        ComplianceCatalogEntry nbspOnlyProjectEntry = new ComplianceCatalogEntry(
                runId,
                "NBSP Product",
                "nbsp-product",
                "1.0.0",
                "Vendor",
                "\u00A0\u2007\u202F\uFEFF",
                "MIT",
                95,
                ColourGradientInfo.from("EMERALD", 95),
                10,
                10,
                "compliance/reports/nbsp-product/1.0.0.json",
                "compliance/badges/nbsp-product.svg",
                "2026-11-14T08:05:00Z"
        );
        CompliancePublicationResult paddedValidResult = CompliancePublicationResult.reconciled(
                runId,
                "\u00A0https://github.com/scimsandbox/scim-website/pull/43\u202F",
                "\uFEFFhttps://scimsandbox.org/compliance/?run=" + runId + "\u2007",
                "\u0085https://scimsandbox.org/compliance/badges/" + runId + ".svg\u00A0",
                "sha-padded",
                OffsetDateTime.now(ZoneOffset.UTC),
                nbspOnlyProjectEntry
        );

        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());
        ValidationRunPublication savedPadded = pubService.recordPublication(
                sampleRun, "user@example.com", requestWithNbspPadding, paddedValidResult);

        assertThat(savedPadded.getProjectUrl()).isNull();
        assertThat(savedPadded.getPrUrl()).isEqualTo("https://github.com/scimsandbox/scim-website/pull/43");
        assertThat(savedPadded.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(savedPadded.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");
    }

    @Test
    void executeRunAndAsync_enforceTargetUrlBoundsBeforeDiscoveryOrPruningAndTruncateRunName() throws Exception {
        java.util.concurrent.atomic.AtomicInteger dnsLookups = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger discoveries = new java.util.concurrent.atomic.AtomicInteger();

        TargetUrlPolicy countingPolicy = new TargetUrlPolicy(false, host -> {
            dnsLookups.incrementAndGet();
            return new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")};
        });

        java.util.concurrent.CountDownLatch asyncDone = new java.util.concurrent.CountDownLatch(2);
        ValidationRunService boundedFieldService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                discoveries.incrementAndGet();
                return 1;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                asyncDone.countDown();
            }
        };
        boundedFieldService.setTargetUrlPolicy(countingPolicy);
        boundedFieldService.setMaxActiveRunsPerUser(1);

        try {
            // 1. Overlong baseUrl (> 500 chars) and internal BOM/NBSP baseUrl must fail at entry BEFORE DNS, discovery, slot leak, or pruning
            String overlongUrl = "https://example.com/" + "a".repeat(481); // 20 + 481 = 501 chars
            String internalBomUrl = "https://example.com/scim/\uFEFFv2";

            for (String badUrl : List.of(overlongUrl, internalBomUrl)) {
                ValidationRunForm badForm = new ValidationRunForm("Bad URL Run", badUrl, "tok");
                assertThatThrownBy(() -> boundedFieldService.executeRun(badForm, "user@example.com"))
                        .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> boundedFieldService.executeRunAsync(badForm, "user@example.com"))
                        .isInstanceOf(IllegalArgumentException.class);
            }
            assertThat(dnsLookups.get()).isZero();
            assertThat(discoveries.get()).isZero();
            verify(runRepository, org.mockito.Mockito.never()).delete(any(ValidationRun.class));
            verify(runRepository, org.mockito.Mockito.never()).save(any(ValidationRun.class));
            verify(runRepository, org.mockito.Mockito.never()).saveAndFlush(any(ValidationRun.class));

            // 2. Exact 500-char URL (after stripping NBSP/BOM padding) and >200-char run name succeed and bound cleanly
            ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
            when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
            when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> {
                ValidationRun r = inv.getArgument(0);
                if (r.getId() == null) {
                    var f = ValidationRun.class.getDeclaredField("id");
                    f.setAccessible(true);
                    f.set(r, runId);
                }
                return r;
            });
            when(runRepository.saveAndFlush(any(ValidationRun.class))).thenAnswer(inv -> {
                ValidationRun r = inv.getArgument(0);
                var f = ValidationRun.class.getDeclaredField("id");
                f.setAccessible(true);
                f.set(r, runId);
                return r;
            });
            when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));

            String exact500Url = "https://example.com/" + "a".repeat(480); // 500 chars
            String overlongSurrogateName = "  " + "N".repeat(199) + "\uD83D\uDE80extra  "; // char 200 is high surrogate -> 199 chars
            ValidationRunForm syncForm = new ValidationRunForm(
                    overlongSurrogateName, "\uFEFF\u00A0" + exact500Url + "\u202F", "tok");
            ValidationRun savedSync = boundedFieldService.executeRun(syncForm, "user@example.com").getRun();
            assertThat(savedSync.getTargetUrl()).isEqualTo(exact500Url).hasSize(500);
            assertThat(savedSync.getName()).isEqualTo("N".repeat(199)).hasSize(199);

            ValidationRunForm asyncForm = new ValidationRunForm(null, "https://example.com/scim/v2", "tok");
            ValidationRun savedAsync = boundedFieldService.executeRunAsync(asyncForm, "user@example.com").getRun();
            assertThat(savedAsync.getName()).isEmpty();
            assertThat(asyncDone.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        } finally {
            boundedFieldService.shutdownExecutor();
        }
    }

    @Test
    void publicationSlugAndFallbackUrls_satisfyLengthHyphenUuidAndMisconfiguredBaseUrlBounds() {
        // 1. Slug bounding: char 120 == '-' strips trailing '-', UUID prefixes with 'product-', empty falls back cleanly
        String hyphenAt120 = "a".repeat(119) + "-b";
        assertThat(ValidationRunService.sanitizeRequestedProductSlug(hyphenAt120, "Fallback"))
                .isEqualTo("a".repeat(119))
                .hasSize(119)
                .doesNotEndWith("-");
        assertThat(ValidationRunService.sanitizeRequestedProductSlug("11111111-1111-1111-1111-111111111111", "Fallback"))
                .isEqualTo("product-11111111-1111-1111-1111-111111111111");
        assertThat(ValidationRunService.sanitizeRequestedProductSlug("---", "My Product!"))
                .isEqualTo("my-product");
        assertThat(ValidationRunService.sanitizeRequestedProductSlug(null, "   "))
                .isEqualTo("scim-product");

        // 2. Misconfigured publicBaseUrl (embedded userinfo or >500 chars) falls back cleanly to scimsandbox.org
        ValidationRunPublicationRepository pubRepo = org.mockito.Mockito.mock(ValidationRunPublicationRepository.class);
        when(pubRepo.save(any(ValidationRunPublication.class))).thenAnswer(inv -> inv.getArgument(0));
        when(runRepository.findById(runId)).thenReturn(Optional.of(sampleRun));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> inv.getArgument(0));

        ValidationRunService pubService = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, pubRepo, progressTracker);

        CompliancePublishRequest edgeSlugRequest = new CompliancePublishRequest(
                runId,
                "Edge Slug Product",
                hyphenAt120,
                "1.0.0",
                null,
                null,
                "MIT",
                false,
                92,
                "EMERALD",
                9,
                10,
                "user@example.com",
                "https://scim.example.com/v2"
        );

        // 2a. Userinfo in publicBaseUrl during reservePublication & recordPublication
        pubService.setPublicBaseUrl("https://admin:secret@scimsandbox.net");
        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());
        ValidationRunPublication reserved = pubService.reservePublication(sampleRun, "user@example.com", edgeSlugRequest);
        assertThat(reserved.getProductSlug()).isEqualTo("a".repeat(119));
        assertThat(reserved.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(reserved.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");

        // 2b. Overlong publicBaseUrl (> 500 chars when path appended) during recordPublication
        pubService.setPublicBaseUrl("https://scimsandbox.net/" + "p".repeat(480));
        sampleRun.setPublication(null);
        when(pubRepo.findById(runId)).thenReturn(Optional.empty());
        CompliancePublicationResult emptyUrlResult = CompliancePublicationResult.reconciled(
                runId, null, null, null, "sha-edge", OffsetDateTime.now(ZoneOffset.UTC), null);
        ValidationRunPublication published = pubService.recordPublication(
                sampleRun, "user@example.com", edgeSlugRequest, emptyUrlResult);
        assertThat(published.getProductSlug()).isEqualTo("a".repeat(119));
        assertThat(published.getReportUrl()).isEqualTo("https://scimsandbox.org/compliance/?run=" + runId);
        assertThat(published.getBadgeUrl()).isEqualTo("https://scimsandbox.org/compliance/badges/" + runId + ".svg");
    }

    @Test
    void shutdownExecutorCancelsQueuedCommittedRunsAndDiscoverTestCountScrubsSecrets() throws Exception {
        Class.forName(de.palsoftware.scim.validator.ui.ScimValidatorManagementApplication.class.getName());
        assertThat(java.security.Security.getProperty("networkaddress.cache.ttl")).isEqualTo("0");

        TargetUrlPolicy publicPolicy = new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")});

        // 1. discoverTestCount scrubs secrets from thrown exceptions (both message and null-message branches)
        ValidationRunService throwingDiscoverSvc = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository, progressTracker, null) {
            private int calls;

            @Override
            org.junit.platform.launcher.TestPlan discoverTestPlan(LauncherDiscoveryRequest request) {
                if (calls++ == 0) {
                    throw new IllegalStateException("Discovery exploded with secret-token-999");
                }
                throw new IllegalStateException((String) null);
            }
        };
        try {
            assertThat(throwingDiscoverSvc.discoverTestCount("https://example.com/scim/v2", "secret-token-999"))
                    .isEqualTo(ValidationRunService.DEFAULT_DISCOVERED_TEST_COUNT);
            assertThat(throwingDiscoverSvc.discoverTestCount("https://example.com/scim/v2", "secret-token-999"))
                    .isEqualTo(ValidationRunService.DEFAULT_DISCOVERED_TEST_COUNT);
        } finally {
            throwingDiscoverSvc.shutdownExecutor();
        }

        // 2. Queued committed async run on owned executor is cancelled cleanly on shutdownExecutor()
        UUID firstRunId = UUID.randomUUID();
        UUID queuedRunId = UUID.randomUUID();
        ValidationRun firstRun = new ValidationRun();
        ValidationRun queuedRun = new ValidationRun();
        var idField = ValidationRun.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(firstRun, firstRunId);
        idField.set(queuedRun, queuedRunId);
        firstRun.setStatus("RUNNING");
        queuedRun.setStatus("RUNNING");

        ValidationMgmtUser owner = new ValidationMgmtUser("user@example.com", OffsetDateTime.now());
        when(mgmtUserRepository.findById("user@example.com")).thenReturn(Optional.of(owner));
        java.util.concurrent.atomic.AtomicInteger saveSeq = new java.util.concurrent.atomic.AtomicInteger();
        when(runRepository.saveAndFlush(any(ValidationRun.class))).thenAnswer(inv ->
                saveSeq.incrementAndGet() == 1 ? firstRun : queuedRun);
        when(runRepository.findById(firstRunId)).thenReturn(Optional.of(firstRun));
        when(runRepository.findById(queuedRunId)).thenReturn(Optional.of(queuedRun));
        when(runRepository.save(any(ValidationRun.class))).thenAnswer(inv -> inv.getArgument(0));

        java.util.concurrent.CountDownLatch workerStarted = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch blockWorker = new java.util.concurrent.CountDownLatch(1);

        ValidationRunService ownedPoolSvc = new ValidationRunService(
                runRepository, mgmtUserRepository, testResultRepository, exchangeRepository,
                null, progressTracker, publicPolicy, null, null, 1, 2) {
            @Override
            int discoverTestCount(String baseUrl, String authToken) {
                return 5;
            }

            @Override
            void executeLauncher(org.junit.platform.launcher.Launcher launcher,
                                 LauncherDiscoveryRequest request,
                                 org.junit.platform.launcher.TestExecutionListener listener) {
                workerStarted.countDown();
                try {
                    blockWorker.await(5, java.util.concurrent.TimeUnit.SECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        ownedPoolSvc.setMaxActiveRunsPerUser(2);

        ValidationRunForm form = new ValidationRunForm("Queued Run", "https://example.com/scim/v2", "secret-token-999");
        ownedPoolSvc.executeRunAsync(form, "user@example.com");
        assertThat(workerStarted.await(3, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

        // Second run sits in the LinkedBlockingQueue behind the 1 busy worker thread
        ownedPoolSvc.executeRunAsync(form, "user@example.com");

        // Shut down executor while run #2 is queued -> drains queue, marks queuedRun ERROR, fails progressTracker
        ownedPoolSvc.shutdownExecutor();
        blockWorker.countDown();

        assertThat(queuedRun.getStatus()).isEqualTo("ERROR");
        verify(progressTracker).failRun(eq(queuedRunId), eq("Validation run cancelled during shutdown"));

        // Edge branches on CancelableAsyncRunTask & cancelDroppedAsyncTasks
        ValidationRunService.cancelDroppedAsyncTasks(null);
        ValidationRunService.CancelableAsyncRunTask edgeTask =
                new ValidationRunService.CancelableAsyncRunTask(ownedPoolSvc, null);
        edgeTask.cancelQueuedOnShutdown();
        edgeTask.cancelQueuedOnShutdown();
        edgeTask.run();

        ValidationRunService.CancelableAsyncRunTask interruptedTask =
                new ValidationRunService.CancelableAsyncRunTask(ownedPoolSvc, null);
        Thread.currentThread().interrupt();
        try {
            interruptedTask.run();
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
        interruptedTask.abortBeforeHandoff();
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