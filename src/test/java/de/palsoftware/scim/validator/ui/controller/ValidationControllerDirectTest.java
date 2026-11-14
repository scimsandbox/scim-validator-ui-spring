package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
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
        controller.setTargetUrlPolicy(new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));
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
        assertThat(body.get("myRunsCount")).isEqualTo(0L);
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

    @Test
    void executeSyncAndAsync_whenRateLimitedOrInvalidUrl_returnExpectedErrorResponses() {
        // setTargetUrlPolicy(null) falls back to strict default policy
        controller.setTargetUrlPolicy(null);
        ValidationRunForm localForm = new ValidationRunForm("Local Run", "http://localhost:8080/scim/v2", "tok");
        BindingResult localBinding = new BeanPropertyBindingResult(localForm, "runForm");
        Model model = new ExtendedModelMap();
        RedirectAttributes redirectAttrs = new RedirectAttributesModelMap();

        String invalidView = controller.execute(localForm, localBinding, model, authentication, redirectAttrs);
        assertThat(invalidView).isEqualTo("index");
        assertThat(localBinding.hasFieldErrors("baseUrl")).isTrue();

        // Restore stubbed policy and simulate 429 ResponseStatusException with non-null and null reason
        controller.setTargetUrlPolicy(new TargetUrlPolicy(
                false, host -> new java.net.InetAddress[]{java.net.InetAddress.getByName("93.184.216.34")}));
        ValidationRunForm validForm = new ValidationRunForm("Burst Run", "https://example.com/scim", "tok");

        runService.throwOnExecute = new org.springframework.web.server.ResponseStatusException(
                HttpStatus.TOO_MANY_REQUESTS, "Rate limit reached");
        ResponseEntity<?> asyncRateLimited = controller.executeAsync(
                validForm, new BeanPropertyBindingResult(validForm, "runForm"), authentication);
        assertThat(asyncRateLimited.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        RedirectAttributes syncRedirect1 = new RedirectAttributesModelMap();
        String syncRateLimited1 = controller.execute(
                validForm, new BeanPropertyBindingResult(validForm, "runForm"), new ExtendedModelMap(), authentication, syncRedirect1);
        assertThat(syncRateLimited1).isEqualTo("redirect:/");
        assertThat(syncRedirect1.getFlashAttributes().get("errorMessage")).isEqualTo("Rate limit reached");

        runService.throwOnExecute = new org.springframework.web.server.ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
        ResponseEntity<?> asyncNullReason = controller.executeAsync(
                validForm, new BeanPropertyBindingResult(validForm, "runForm"), authentication);
        assertThat(asyncNullReason.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        RedirectAttributes syncRedirect2 = new RedirectAttributesModelMap();
        String syncRateLimited2 = controller.execute(
                validForm, new BeanPropertyBindingResult(validForm, "runForm"), new ExtendedModelMap(), authentication, syncRedirect2);
        assertThat(syncRateLimited2).isEqualTo("redirect:/");
        assertThat(syncRedirect2.getFlashAttributes().get("errorMessage")).isEqualTo("Too many concurrent validation runs.");

        // Controller syntax validation performs 0 DNS lookups; DNS/address errors from ValidationRunService map to baseUrl field errors
        controller.setTargetUrlPolicy(new TargetUrlPolicy(false, host -> {
            throw new AssertionError("ValidationController must use validateSyntax without DNS lookup");
        }));
        runService.throwOnExecute = null;
        runService.throwIllegalArgOnExecute = new IllegalArgumentException(
                "Invalid URL: private RFC 1918 target addresses are not allowed");

        BindingResult syncDnsBinding = new BeanPropertyBindingResult(validForm, "runForm");
        String syncDnsErrorView = controller.execute(
                validForm, syncDnsBinding, new ExtendedModelMap(), authentication, new RedirectAttributesModelMap());
        assertThat(syncDnsErrorView).isEqualTo("index");
        assertThat(syncDnsBinding.hasFieldErrors("baseUrl")).isTrue();

        BindingResult asyncDnsBinding = new BeanPropertyBindingResult(validForm, "runForm");
        ResponseEntity<?> asyncDnsError = controller.executeAsync(validForm, asyncDnsBinding, authentication);
        assertThat(asyncDnsError.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        @SuppressWarnings("unchecked")
        Map<String, Object> asyncErrorBody = (Map<String, Object>) asyncDnsError.getBody();
        assertThat(asyncErrorBody).containsKey("errors");
    }

    @Test
    void publishRun_whenReconciliationFindsExistingPublication_redirectsWithSuccessMessage() {
        UUID runId = runService.createdRun.getId();
        runService.reconciliationRequired = true;
        de.palsoftware.scim.validator.ui.model.ValidationRunPublication pub =
                new de.palsoftware.scim.validator.ui.model.ValidationRunPublication();
        pub.setRunId(runId);
        pub.setReportUrl("https://scimsandbox.net/compliance/?run=" + runId);
        runService.existingPublication = pub;

        Authentication adminAuth = new TestingAuthenticationToken(
                "admin@example.com",
                "n/a",
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        de.palsoftware.scim.validator.ui.dto.CompliancePublishFormData publishForm =
                new de.palsoftware.scim.validator.ui.dto.CompliancePublishFormData();
        BindingResult bindingResult = new BeanPropertyBindingResult(publishForm, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        String view = controller.publishRun(runId, publishForm, bindingResult, adminAuth, redirectAttributes);

        assertThat(view).isEqualTo("redirect:/runs/" + runId);
        assertThat(String.valueOf(redirectAttributes.getFlashAttributes().get("successMessage")))
                .contains("https://scimsandbox.net/compliance/?run=" + runId);
    }

    // --- Test Doubles ---

    private static class TestValidationRunService extends ValidationRunService {
        private final ValidationRun createdRun;
        private org.springframework.web.server.ResponseStatusException throwOnExecute;
        private IllegalArgumentException throwIllegalArgOnExecute;
        private boolean reconciliationRequired;
        private de.palsoftware.scim.validator.ui.model.ValidationRunPublication existingPublication;

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
            if (throwIllegalArgOnExecute != null) {
                throw throwIllegalArgOnExecute;
            }
            if (throwOnExecute != null) {
                throw throwOnExecute;
            }
            return new ExecutionResult(createdRun, false, 10);
        }

        @Override
        public ExecutionResult executeRun(ValidationRunForm form, String actorEmail) {
            if (throwIllegalArgOnExecute != null) {
                throw throwIllegalArgOnExecute;
            }
            if (throwOnExecute != null) {
                throw throwOnExecute;
            }
            return new ExecutionResult(createdRun, false, 10);
        }

        @Override
        public ValidationRun getRunEntity(UUID runId, String actorEmail, boolean admin) {
            return createdRun;
        }

        @Override
        public boolean isReconciliationRequired(UUID runId) {
            return reconciliationRequired;
        }

        @Override
        public java.util.Optional<de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult> tryReconcilePendingPublication(ValidationRun run) {
            return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<de.palsoftware.scim.validator.ui.model.ValidationRunPublication> getPublication(UUID runId) {
            return java.util.Optional.ofNullable(existingPublication);
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

        @Override
        public long countOwnedRuns(String actorEmail) {
            return 0;
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
