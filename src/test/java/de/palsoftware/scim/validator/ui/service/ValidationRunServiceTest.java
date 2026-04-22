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
import org.junit.platform.launcher.LauncherDiscoveryRequest;
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

    // ─── helpers ────────────────────────────────────────────────────────

    private static void restoreProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}