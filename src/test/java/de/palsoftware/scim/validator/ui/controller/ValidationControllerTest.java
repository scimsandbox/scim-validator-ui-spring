package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidationControllerTest {

    @Mock
    private ValidationRunService validationRunService;

    @Mock
    private MgmtUserService mgmtUserService;

    @Mock
    private ValidationProgressTracker validationProgressTracker;

    @InjectMocks
    private ValidationController controller;

    private Model model;
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        model = new ExtendedModelMap();
        authentication = new TestingAuthenticationToken("user@example.com", "n/a");
    }

    @Test
    void index_addsRunFormWhenNotPresent() {
        when(validationRunService.listRuns(anyString(), anyBoolean()))
                .thenReturn(Collections.emptyList());

        String view = controller.index(model, authentication);

        assertThat(view).isEqualTo("index");
        assertThat(model.containsAttribute("runForm")).isTrue();
        assertThat(model.containsAttribute("runs")).isTrue();
        assertThat(model.containsAttribute("currentUser")).isTrue();
    }

    @Test
    void index_preservesExistingRunForm() {
        ValidationRunForm existingForm = new ValidationRunForm("existing", "http://existing.url", "token");
        model.addAttribute("runForm", existingForm);

        when(validationRunService.listRuns(anyString(), anyBoolean()))
                .thenReturn(Collections.emptyList());

        controller.index(model, authentication);

        assertThat(model.getAttribute("runForm")).isSameAs(existingForm);
    }

    @Test
    void execute_withValidationErrors_returnsIndexView() {
        ValidationRunForm form = new ValidationRunForm("", "", "");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");
        bindingResult.rejectValue("name", "NotBlank");

        when(validationRunService.listRuns(anyString(), anyBoolean()))
                .thenReturn(Collections.emptyList());

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        String view = controller.execute(form, bindingResult, model, authentication, redirectAttributes);

        assertThat(view).isEqualTo("index");
        assertThat(model.containsAttribute("runs")).isTrue();
    }

    @Test
    void execute_success_redirectsToRunDetail() {
        ValidationRunForm form = new ValidationRunForm("Test Run", "https://example.com/scim", "token");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");

        ValidationRun run = new ValidationRun();
        run.setName("Test Run");
        run.setTargetUrl("https://example.com/scim");
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("PASSED");
        run.setCreatedByUser(new ValidationMgmtUser("user@example.com", OffsetDateTime.now()));
        run.setTotalTests(5);
        run.setPassedTests(5);
        run.setFailedTests(0);
        // Use reflection to set the id since there's no setter
        try {
            var idField = ValidationRun.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(run, UUID.randomUUID());
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }

        when(validationRunService.executeRun(org.mockito.ArgumentMatchers.eq(form), anyString()))
                .thenReturn(new ValidationRunService.ExecutionResult(run, false, 10));

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        String view = controller.execute(form, bindingResult, model, authentication, redirectAttributes);

        assertThat(view).startsWith("redirect:/runs/");
        org.mockito.Mockito.verify(validationRunService).executeRun(org.mockito.ArgumentMatchers.eq(form), anyString());
    }

    @Test
    void detail_populatesModel() {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = new ValidationRunView(
                runId, "Test", "http://example.com", OffsetDateTime.now(),
                "PASSED", "user@example.com", 10, 10, 0);
        List<ValidationTestResultView> testResults = Collections.emptyList();

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(testResults);

        String view = controller.detail(runId, model, authentication);

        assertThat(view).isEqualTo("run-detail");
        assertThat(model.getAttribute("run")).isEqualTo(runView);
        assertThat(model.getAttribute("tests")).isEqualTo(testResults);
    }

    @Test
    void deleteRun_redirectsToRoot() {
        UUID runId = UUID.randomUUID();

        String view = controller.deleteRun(runId, authentication);

        assertThat(view).isEqualTo("redirect:/");
        verify(validationRunService).deleteRun(eq(runId), anyString(), anyBoolean());
    }

    @Test
    void executeAsync_withValidationErrors_returnsBadRequest() {
        ValidationRunForm form = new ValidationRunForm("", "", "");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");
        bindingResult.rejectValue("name", "NotBlank", "Name is required");

        ResponseEntity<?> response = controller.executeAsync(form, bindingResult, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsKey("errors");
    }

    @Test
    void executeAsync_success_returnsOkWithRunId() {
        ValidationRunForm form = new ValidationRunForm("Test Run", "https://example.com/scim", "token");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");

        UUID runId = UUID.randomUUID();
        ValidationRun run = new ValidationRun();
        run.setName("Test Run");
        run.setTargetUrl("https://example.com/scim");
        run.setExecutedAt(OffsetDateTime.now());
        run.setStatus("RUNNING");
        run.setTotalTests(52);
        try {
            var idField = ValidationRun.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(run, runId);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }

        when(validationRunService.executeRunAsync(eq(form), anyString()))
                .thenReturn(new ValidationRunService.ExecutionResult(run, false, 10));

        ResponseEntity<?> response = controller.executeAsync(form, bindingResult, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        assertThat(body.get("runId")).isEqualTo(runId.toString());
        assertThat(body.get("totalTests")).isEqualTo(52);
        assertThat(body.get("redirectUrl")).isEqualTo("/runs/" + runId);
    }

    @Test
    void streamProgress_subscribesToTracker() {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = new ValidationRunView(
                runId, "Test", "http://example.com", OffsetDateTime.now(),
                "RUNNING", "user@example.com", 52, 0, 0);
        SseEmitter emitter = new SseEmitter();

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationProgressTracker.subscribe(runId)).thenReturn(emitter);

        SseEmitter result = controller.streamProgress(runId, authentication);

        assertThat(result).isSameAs(emitter);
        verify(validationRunService).getRun(eq(runId), anyString(), anyBoolean());
        verify(validationProgressTracker).subscribe(runId);
    }

    @Test
    void getStatus_returnsCurrentProgress() {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = new ValidationRunView(
                runId, "Test", "http://example.com", OffsetDateTime.now(),
                "RUNNING", "user@example.com", 52, 10, 0);
        ValidationProgress progress = ValidationProgress.running(
                runId, 10, 52, 10, 0, "A2_SchemaValidationSpec", "Test schema", "/runs/" + runId);

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationProgressTracker.getProgress(runId)).thenReturn(progress);

        ResponseEntity<ValidationProgress> response = controller.getStatus(runId, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(progress);
    }
}
