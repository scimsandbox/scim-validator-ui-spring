package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ValidationControllerDirectTest {

    private TestValidationRunService runService;
    private ValidationProgressTracker progressTracker;
    private ValidationController controller;
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        runService = new TestValidationRunService();
        progressTracker = new ValidationProgressTracker();
        controller = new ValidationController(runService, new TestMgmtUserService(), progressTracker, "https://manager.example.com");
        authentication = new TestingAuthenticationToken("testuser@example.com", "n/a");
    }

    @Test
    void executeAsync_withInvalidUrl_returnsBadRequestWithErrors() {
        ValidationRunForm form = new ValidationRunForm("Test", "ftp://invalid-url", "token");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");

        ResponseEntity<?> response = controller.executeAsync(form, bindingResult, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsKey("errors");
    }

    @Test
    void executeAsync_withValidForm_startsRunAndReturnsRunId() {
        ValidationRunForm form = new ValidationRunForm("Nightly Run", "https://example.com/scim", "secret-token");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");

        ResponseEntity<?> response = controller.executeAsync(form, bindingResult, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body.get("runId")).isEqualTo(runService.createdRun.getId().toString());
        assertThat(body.get("totalTests")).isEqualTo(52);
        assertThat(body.get("redirectUrl")).isEqualTo("/runs/" + runService.createdRun.getId());
    }

    @Test
    void streamProgress_returnsSseEmitter() {
        UUID runId = runService.createdRun.getId();

        SseEmitter emitter = controller.streamProgress(runId, authentication);

        assertThat(emitter).isNotNull();
    }

    @Test
    void getStatus_returnsCurrentProgressFromTracker() {
        UUID runId = runService.createdRun.getId();
        progressTracker.registerRun(runId, 52, "/runs/" + runId);
        progressTracker.updateProgress(runId, 12, 52, 12, 0, "A3_UserCrudSpec", "Create User");

        ResponseEntity<ValidationProgress> response = controller.getStatus(runId, authentication);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().currentTestIndex()).isEqualTo(12);
        assertThat(response.getBody().totalTests()).isEqualTo(52);
        assertThat(response.getBody().remainingTests()).isEqualTo(40);
        assertThat(response.getBody().currentSpec()).isEqualTo("A3_UserCrudSpec");
    }


    @Test
    void executeSync_redirectsToRunDetail() {
        ValidationRunForm form = new ValidationRunForm("Nightly Run", "https://example.com/scim", "secret-token");
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "runForm");
        Model model = new ExtendedModelMap();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        String view = controller.execute(form, bindingResult, model, authentication, redirectAttributes);

        assertThat(view).isEqualTo("redirect:/runs/" + runService.createdRun.getId());
    }

    // --- Test Doubles ---

    private static class TestValidationRunService extends ValidationRunService {
        private final ValidationRun createdRun;

        public TestValidationRunService() {
            super(null, null, null, null, null);
            createdRun = new ValidationRun();
            createdRun.setName("Test Run");
            createdRun.setTargetUrl("https://example.com/scim");
            createdRun.setExecutedAt(OffsetDateTime.now());
            createdRun.setStatus("RUNNING");
            createdRun.setCreatedByUser(new de.palsoftware.scim.validator.ui.model.ValidationMgmtUser("testuser@example.com", OffsetDateTime.now()));
            createdRun.setTotalTests(52);
            try {
                var idField = ValidationRun.class.getDeclaredField("id");
                idField.setAccessible(true);
                idField.set(createdRun, UUID.randomUUID());
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public ExecutionResult executeRunAsync(ValidationRunForm form, String actorEmail) {
            return new ExecutionResult(createdRun, false, 10);
        }

        @Override
        public ExecutionResult executeRun(ValidationRunForm form, String actorEmail) {
            return new ExecutionResult(createdRun, false, 10);
        }

        @Override
        public ValidationRunView getRun(UUID runId, String actorEmail, boolean admin) {
            return ValidationRunView.from(createdRun);
        }

        @Override
        public List<ValidationRunView> listRuns(String actorEmail, boolean admin) {
            return List.of(ValidationRunView.from(createdRun));
        }

        @Override
        public int getMaxRunsPerUser() {
            return 10;
        }
    }

    private static class TestMgmtUserService extends MgmtUserService {
        public TestMgmtUserService() {
            super(null);
        }

        @Override
        public String resolveDisplayName(String email, String fallback) {
            return fallback != null ? fallback : email;
        }
    }
}
