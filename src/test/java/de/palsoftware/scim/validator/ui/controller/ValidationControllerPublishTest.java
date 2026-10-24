package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.CompliancePublishFormData;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.spec.ColourGradient;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceScorecardView;
import de.palsoftware.scim.validator.ui.model.spec.NormativeBreakdown;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.service.ComplianceScoreService;
import de.palsoftware.scim.validator.ui.service.GitHubCompliancePublisherService;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.SpecCatalogService;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidationControllerPublishTest {

    @Mock
    private ValidationRunService validationRunService;

    @Mock
    private MgmtUserService mgmtUserService;

    @Mock
    private ValidationProgressTracker validationProgressTracker;

    @Mock
    private ComplianceScoreService complianceScoreService;

    @Mock
    private SpecCatalogService specCatalogService;

    @Mock
    private GitHubCompliancePublisherService gitHubCompliancePublisherService;

    @Mock
    private ValidationRunPublicationRepository publicationRepository;

    private ValidationController controller;
    private Authentication userAuth;
    private Authentication adminAuth;

    @BeforeEach
    void setUp() {
        controller = new ValidationController(
                validationRunService,
                mgmtUserService,
                validationProgressTracker,
                "https://manager.example.com",
                complianceScoreService,
                specCatalogService,
                gitHubCompliancePublisherService,
                publicationRepository
        );
        userAuth = new TestingAuthenticationToken("developer@example.com", "n/a");
        adminAuth = new TestingAuthenticationToken("admin@example.com", "n/a",
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Index Endpoint Tests (Published Runs & Quota)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void index_populatesPublishedRunsModelAndQuotaAttributes() {
        Model model = new ExtendedModelMap();
        ValidationRunPublication samplePub = createSamplePublication(UUID.randomUUID(), "developer@example.com", 92);

        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(Collections.emptyList());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(eq("developer@example.com"), eq(false)))
                .thenReturn(List.of(samplePub));
        when(validationRunService.countOwnedPublications("developer@example.com")).thenReturn(1L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        String view = controller.index(null, model, userAuth);

        assertThat(view).isEqualTo("index");
        assertThat(model.getAttribute("publishedRuns")).isEqualTo(List.of(samplePub));
        assertThat(((Number) model.getAttribute("publishedCount")).intValue()).isEqualTo(1);
        assertThat(((Number) model.getAttribute("publishedRunsCount")).intValue()).isEqualTo(1);
        assertThat(((Number) model.getAttribute("myPublishedRunsCount")).longValue()).isEqualTo(1L);
        assertThat(model.getAttribute("maxPublishedRuns")).isEqualTo(50);
        assertThat(model.getAttribute("publishedQuotaMax")).isEqualTo(50);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Detail Endpoint Tests (Scorecard, Eligibility & Spec Mappings)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void detail_withEligibleUnpublishedRun_populatesScorecardAndEligibility() {
        UUID runId = UUID.randomUUID();
        Model model = new ExtendedModelMap();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ValidationRunView runView = ValidationRunView.from(runEntity);
        ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

        when(validationRunService.getRun(runId, "developer@example.com", false)).thenReturn(runView);
        when(validationRunService.getTestResults(runId, "developer@example.com", false)).thenReturn(Collections.emptyList());
        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList()))
                .thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of("DSC_01", new TestSpecMapping("DSC_01", "Service Discovery", "specs.A1_ServiceDiscoverySpec", "none", List.of("RFC7644-4-R1"))));
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        String view = controller.detail(runId, model, userAuth);

        assertThat(view).isEqualTo("run-detail");
        assertThat(model.getAttribute("scorecard")).isEqualTo(scorecard);
        assertThat(model.getAttribute("isEligibleForPublish")).isEqualTo(true);
        assertThat(model.getAttribute("publication")).isNull();
        assertThat(model.getAttribute("isPublished")).isEqualTo(false);
        assertThat(model.containsAttribute("publishForm")).isTrue();
        assertThat(model.containsAttribute("testSpecMappings")).isTrue();
    }

    @Test
    void detail_withPublishedRun_populatesPublicationRecord() {
        UUID runId = UUID.randomUUID();
        Model model = new ExtendedModelMap();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ValidationRunPublication publication = createSamplePublication(runId, "developer@example.com", 95);
        runEntity.setPublication(publication);
        ValidationRunView runView = ValidationRunView.from(runEntity);
        ComplianceScorecardView scorecard = createSampleScorecard(95, true, null);

        when(validationRunService.getRun(runId, "developer@example.com", false)).thenReturn(runView);
        when(validationRunService.getTestResults(runId, "developer@example.com", false)).thenReturn(Collections.emptyList());
        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList()))
                .thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);

        String view = controller.detail(runId, model, userAuth);

        assertThat(view).isEqualTo("run-detail");
        assertThat(model.getAttribute("publication")).isEqualTo(publication);
        assertThat(model.getAttribute("isPublished")).isEqualTo(true);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Publish Endpoint Tests: POST /runs/{runId}/publish
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void publishRun_happyPath_publishesToGitHubAndPersistsPublication() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);
        CompliancePublicationResult pubResult = new CompliancePublicationResult(
                true,
                runId,
                "https://github.com/scimsandbox/scim-website/pull/12",
                "https://scimsandbox.net/compliance/?run=" + runId,
                "https://scimsandbox.net/compliance/badges/" + runId + ".svg",
                "sha123456",
                null
        );

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", "ASF", "https://syncope.apache.org", "Apache-2.0", true
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
        when(gitHubCompliancePublisherService.publish(any(CompliancePublishRequest.class))).thenReturn(pubResult);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("successMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("justPublished")).isEqualTo(true);
        verify(validationRunService).recordPublication(eq(runEntity), eq("developer@example.com"), any(CompliancePublishRequest.class), eq(pubResult));
    }

    @Test
    void publishRun_alreadyPublished_rejectsWithErrorMessage() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        runEntity.setPublication(createSamplePublication(runId, "developer@example.com", 90));

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", null, null, "Apache-2.0", false
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString()).contains("already been published");
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_quotaExceeded_rejectsWithoutPublishing() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", null, null, "Apache-2.0", false
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        org.mockito.Mockito.doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "User has reached maximum published compliance runs cap (50)."))
                .when(validationRunService).validatePublishQuota("developer@example.com");

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString()).contains("maximum published compliance runs cap");
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_ineligibleScorecard_rejectsWithoutPublishing() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "FAILED");
        ComplianceScorecardView scorecard = createSampleScorecard(42, false, "Core RFC Conformance (42%) is below the minimum 50% publishing threshold");

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", null, null, "Apache-2.0", false
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(false);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString()).contains("below the minimum 50% publishing threshold");
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_formValidationErrors_rejectsWithoutPublishing() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");

        // Invalid form: blank product name
        CompliancePublishFormData form = new CompliancePublishFormData("", "invalid_slug!", "", null, "not-a-url", "", false);
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        bindingResult.rejectValue("productName", "NotBlank", "Product name is required");
        bindingResult.rejectValue("productVersion", "NotBlank", "Product version is required");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString()).contains("Validation error");
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_publisherThrowsException_catchesAndRedirectsWithError() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", null, null, "Apache-2.0", false
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
        when(gitHubCompliancePublisherService.publish(any())).thenThrow(new RuntimeException("GitHub API 503 Service Unavailable"));

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString()).contains("GitHub publishing failed");
        verify(gitHubCompliancePublisherService).releaseClaim(runId);
        verify(validationRunService).releasePublicationReservation(runEntity);
        verify(validationRunService, never()).recordPublication(any(), any(), any(), any());
    }

    @Test
    void publishRun_targetHostInProductName_rejectsWithFriendlyErrorWithoutCallingPublisher() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Internal Server at scim.example.com", "internal-server", "1.0.0", "Vendor",
                "https://github.com/org/repo", "Apache-2.0", false
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                .contains("must not contain the validation target host (scim.example.com)");
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_targetHostInProductVersionOrLicense_rejectsWithFriendlyErrorWithoutCallingPublisher() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");

        CompliancePublishFormData formWithHostInVersion = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "1.0-scim.example.com", "Vendor",
                "https://github.com/org/repo", "Apache-2.0", false
        );
        BindingResult bindingResult1 = new BeanPropertyBindingResult(formWithHostInVersion, "publishForm");
        RedirectAttributes redirectAttributes1 = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);

        String redirect1 = controller.publishRun(runId, formWithHostInVersion, bindingResult1, userAuth, redirectAttributes1);
        assertThat(redirect1).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes1.getFlashAttributes().get("errorMessage").toString())
                .contains("must not contain the validation target host (scim.example.com)");

        CompliancePublishFormData formWithHostInLicense = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "1.0.0", "Vendor",
                "https://github.com/org/repo", "scim.example.com", false
        );
        BindingResult bindingResult2 = new BeanPropertyBindingResult(formWithHostInLicense, "publishForm");
        RedirectAttributes redirectAttributes2 = new RedirectAttributesModelMap();

        String redirect2 = controller.publishRun(runId, formWithHostInLicense, bindingResult2, userAuth, redirectAttributes2);
        assertThat(redirect2).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes2.getFlashAttributes().get("errorMessage").toString())
                .contains("must not contain the validation target host (scim.example.com)");
        verify(validationRunService, never()).reservePublication(any(), any(), any());
        verify(gitHubCompliancePublisherService, never()).publish(any());
    }

    @Test
    void publishRun_pendingReservation_rejectsWhenFreshAndRetriesWhenStale() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ValidationRunPublication pending = new ValidationRunPublication();
        pending.setRun(runEntity);
        pending.setPrUrl(ValidationRunPublication.PENDING_RESERVATION_PR_URL);
        pending.setPublishedAt(OffsetDateTime.now());
        runEntity.setPublication(pending);

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", "ASF", "https://syncope.apache.org", "Apache-2.0", true
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes freshRedirectAttrs = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.isStaleReservation(pending)).thenReturn(false);

        String freshRedirect = controller.publishRun(runId, form, bindingResult, userAuth, freshRedirectAttrs);
        assertThat(freshRedirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(freshRedirectAttrs.getFlashAttributes().get("errorMessage").toString())
                .contains("already in progress");
        verify(gitHubCompliancePublisherService, never()).publish(any());

        // Now mark the reservation stale -> retry succeeds
        when(validationRunService.isStaleReservation(pending)).thenReturn(true);
        ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);
        CompliancePublicationResult pubResult = CompliancePublicationResult.success(
                runId,
                "https://github.com/scimsandbox/scim-website/pull/15",
                "https://scimsandbox.net/compliance/?run=" + runId,
                "https://scimsandbox.net/compliance/badges/" + runId + ".svg",
                "sha999", OffsetDateTime.now()
        );
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
        when(gitHubCompliancePublisherService.publish(any())).thenReturn(pubResult);

        RedirectAttributes staleRedirectAttrs = new RedirectAttributesModelMap();
        String staleRedirect = controller.publishRun(runId, form, bindingResult, userAuth, staleRedirectAttrs);
        assertThat(staleRedirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(staleRedirectAttrs.getFlashAttributes()).containsKey("successMessage");
        verify(validationRunService).reservePublication(eq(runEntity), eq("developer@example.com"), any());
        verify(validationRunService).recordPublication(eq(runEntity), eq("developer@example.com"), any(), eq(pubResult));
    }

    @Test
    void slugify_handlesLongHyphenRunsInLinearTime() {
        String adversarial = "-".repeat(50_000) + "  SCIM 2.0 --- Server___Impl  " + "-".repeat(50_000);
        CompliancePublishFormData form = new CompliancePublishFormData(adversarial, "", "1.0.0", null, null, "MIT", false);
        assertThat(form.resolveProductSlug()).isEqualTo("scim-2-0-server-impl");
        assertThat(CompliancePublishFormData.slugify("---!!!---")).isEmpty();
        assertThat(new CompliancePublishFormData("---!!!---", "", "1.0.0", null, null, "MIT", false).resolveProductSlug())
                .isEmpty();
    }

    @Test
    void publishRun_recordPublicationThrows_retriesAndRetainsClaimAndReservation() {
        UUID runId = UUID.randomUUID();
        ValidationRun runEntity = createSampleRun(runId, "developer@example.com", "PASSED");
        ComplianceScorecardView scorecard = createSampleScorecard(92, true, null);
        CompliancePublicationResult pubResult = new CompliancePublicationResult(
                true, runId,
                "https://github.com/scimsandbox/scim-website/pull/12",
                "https://scimsandbox.net/compliance/?run=" + runId,
                "https://scimsandbox.net/compliance/badges/" + runId + ".svg",
                "sha123456", null
        );

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", "ASF", "https://syncope.apache.org", "Apache-2.0", true
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(Collections.emptyList());
        when(validationRunService.getRawExchanges(runId)).thenReturn(Collections.emptyList());
        when(complianceScoreService.computeScorecard(runEntity, Collections.emptyList(), Collections.emptyList())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(gitHubCompliancePublisherService.isEnabled()).thenReturn(true);
        when(gitHubCompliancePublisherService.publish(any(CompliancePublishRequest.class))).thenReturn(pubResult);
        org.mockito.Mockito.doThrow(new RuntimeException("DB connection lost"))
                .when(validationRunService).recordPublication(eq(runEntity), eq("developer@example.com"), any(CompliancePublishRequest.class), eq(pubResult));

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);

        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes()).containsKey("errorMessage");
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                .contains("locked for reconciliation");
        verify(validationRunService, org.mockito.Mockito.times(2))
                .recordPublication(eq(runEntity), eq("developer@example.com"), any(CompliancePublishRequest.class), eq(pubResult));
        verify(validationRunService).markReconciliationRequired(
                eq(runId), eq("developer@example.com"), any(CompliancePublishRequest.class), eq(pubResult));
        verify(gitHubCompliancePublisherService, never()).releaseClaim(runId);
        verify(validationRunService, never()).releasePublicationReservation(runEntity);

        // If the DB is still unavailable on retry (tryReconcilePendingPublication returns empty) and publish throws,
        // a reconciliation-locked run must NOT release the claim or reservation
        when(validationRunService.isReconciliationRequired(runId)).thenReturn(true);
        when(validationRunService.tryReconcilePendingPublication(runEntity)).thenReturn(java.util.Optional.empty());
        when(gitHubCompliancePublisherService.publish(any(CompliancePublishRequest.class)))
                .thenThrow(new IllegalStateException("Validation run has already been published: " + runId));

        RedirectAttributes retryRedirectAttributes = new RedirectAttributesModelMap();
        String retryRedirect = controller.publishRun(runId, form, bindingResult, userAuth, retryRedirectAttributes);
        assertThat(retryRedirect).isEqualTo("redirect:/runs/" + runId);
        verify(gitHubCompliancePublisherService, never()).releaseClaim(runId);
        verify(validationRunService, never()).releasePublicationReservation(runEntity);

        // Once the DB recovers, retrying publishRun while the PENDING reservation is still present auto-heals
        // via tryReconcilePendingPublication without calling GitHub again or returning "already in progress"
        ValidationRunPublication pendingPub = createSamplePublication(runId, "developer@example.com", 94);
        pendingPub.setPrUrl(ValidationRunPublication.PENDING_RESERVATION_PR_URL);
        runEntity.setPublication(pendingPub);
        when(validationRunService.tryReconcilePendingPublication(runEntity)).thenReturn(java.util.Optional.of(pubResult));

        RedirectAttributes healedRedirectAttributes = new RedirectAttributesModelMap();
        String healedRedirect = controller.publishRun(runId, form, bindingResult, userAuth, healedRedirectAttributes);
        assertThat(healedRedirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(healedRedirectAttributes.getFlashAttributes()).containsKey("successMessage");
        assertThat(healedRedirectAttributes.getFlashAttributes().get("justPublished")).isEqualTo(true);
        verify(gitHubCompliancePublisherService, org.mockito.Mockito.times(2)).publish(any(CompliancePublishRequest.class));

        // If the background reconciler already finalized the publication right before tryReconcilePendingPublication
        // (so tryReconcilePendingPublication returns empty, but getPublication(runId) is present), redirect with successMessage
        ValidationRunPublication finalizedPub = createSamplePublication(runId, "developer@example.com", 94);
        when(validationRunService.tryReconcilePendingPublication(runEntity)).thenReturn(java.util.Optional.empty());
        when(validationRunService.getPublication(runId)).thenReturn(java.util.Optional.of(finalizedPub));

        RedirectAttributes raceHealedRedirectAttributes = new RedirectAttributesModelMap();
        String raceHealedRedirect = controller.publishRun(runId, form, bindingResult, userAuth, raceHealedRedirectAttributes);
        assertThat(raceHealedRedirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(raceHealedRedirectAttributes.getFlashAttributes()).containsKey("successMessage");
        assertThat(raceHealedRedirectAttributes.getFlashAttributes().get("justPublished")).isEqualTo(true);
    }

    @Test
    void publishForm_rejectsControlCharactersInProductNameAndVendorName() {
        try (jakarta.validation.ValidatorFactory factory = jakarta.validation.Validation.buildDefaultValidatorFactory()) {
            jakarta.validation.Validator beanValidator = factory.getValidator();

            CompliancePublishFormData badNameForm = new CompliancePublishFormData(
                    "Apache Syncope\nCo-authored-by: attacker", "apache-syncope", "3.0.0",
                    "ASF", "https://syncope.apache.org", "Apache-2.0", false
            );
            assertThat(beanValidator.validate(badNameForm))
                    .anyMatch(v -> "productName".equals(v.getPropertyPath().toString())
                            && v.getMessage().contains("control characters"));

            CompliancePublishFormData badVendorForm = new CompliancePublishFormData(
                    "Apache Syncope", "apache-syncope", "3.0.0",
                    "ASF\r\nInjected", "https://syncope.apache.org", "Apache-2.0", false
            );
            assertThat(beanValidator.validate(badVendorForm))
                    .anyMatch(v -> "vendorName".equals(v.getPropertyPath().toString())
                            && v.getMessage().contains("control characters"));
        }
    }

    @Test
    void publishRun_rejectsBlankTargetUrlAndUuidFormattedProductSlug() {
        UUID runId = UUID.randomUUID();
        ValidationRun blankTargetRun = createSampleRun(runId, "developer@example.com", "PASSED");
        blankTargetRun.setTargetUrl("   ");

        CompliancePublishFormData form = new CompliancePublishFormData(
                "Apache Syncope", "apache-syncope", "3.0.0", "ASF", "https://syncope.apache.org", "Apache-2.0", true
        );
        BindingResult bindingResult = new BeanPropertyBindingResult(form, "publishForm");
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(validationRunService.getRunEntity(runId, "developer@example.com", false)).thenReturn(blankTargetRun);

        String redirect = controller.publishRun(runId, form, bindingResult, userAuth, redirectAttributes);
        assertThat(redirect).isEqualTo("redirect:/runs/" + runId);
        assertThat(redirectAttributes.getFlashAttributes().get("errorMessage").toString())
                .contains("missing a target URL");
        verify(gitHubCompliancePublisherService, never()).publish(any());

        // Auto-slugification of a UUID product name prefixes "product-" so it never collides with a run badge UUID
        CompliancePublishFormData uuidNamedForm = new CompliancePublishFormData(
                "550e8400-e29b-41d4-a716-446655440000", "", "1.0.0", null, null, "MIT", false
        );
        assertThat(uuidNamedForm.resolveProductSlug()).isEqualTo("product-550e8400-e29b-41d4-a716-446655440000");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Factories
    // ─────────────────────────────────────────────────────────────────────────

    private ValidationRun createSampleRun(UUID runId, String userEmail, String status) {
        ValidationRun run = new ValidationRun();
        ReflectionTestUtils.setField(run, "id", runId);
        run.setName("Sample SCIM Validation");
        run.setTargetUrl("https://scim.example.com");
        run.setStatus(status);
        run.setTotalTests(52);
        run.setPassedTests(50);
        run.setFailedTests(2);
        run.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        ValidationMgmtUser user = new ValidationMgmtUser(userEmail, OffsetDateTime.now(ZoneOffset.UTC));
        run.setCreatedByUser(user);
        return run;
    }

    private ValidationRunPublication createSamplePublication(UUID runId, String userEmail, int score) {
        ValidationRunPublication pub = new ValidationRunPublication();
        pub.setRunId(runId);
        pub.setCreatedByEmail(userEmail);
        pub.setProductName("Sample SCIM Product");
        pub.setProductSlug("sample-scim-product");
        pub.setProductVersion("1.0.0");
        pub.setVendorName("Sample Org");
        pub.setLicenseType("Apache-2.0");
        pub.setShowSubmitter(false);
        pub.setCoreScore(score);
        pub.setSupportedCapabilities(9);
        pub.setTotalCapabilities(10);
        pub.setReportUrl("https://scimsandbox.net/compliance/?run=" + runId);
        pub.setBadgeUrl("https://scimsandbox.net/compliance/badges/" + runId + ".svg");
        pub.setPrUrl("https://github.com/scimsandbox/scim-website/pull/1");
        pub.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return pub;
    }

    private ComplianceScorecardView createSampleScorecard(int score, boolean eligible, String reason) {
        ColourGradient gradient = ColourGradient.forScore(score);
        return new ComplianceScorecardView(
                UUID.randomUUID(), "Sample SCIM Validation", "https://scim.example.com", OffsetDateTime.now(ZoneOffset.UTC), "PASSED",
                score, gradient,
                eligible,
                reason,
                NormativeBreakdown.of("MUST", 3, 132, 130, 2, 0, 390.0, 396.0),
                NormativeBreakdown.of("SHOULD", 2, 9, 8, 1, 0, 16.0, 18.0),
                NormativeBreakdown.of("MAY", 1, 3, 3, 0, 0, 3.0, 3.0),
                Collections.emptyList(), 9, 8, 10,
                157, 144, 0, 13,
                Collections.emptyMap(), Collections.emptyList()
        );
    }
}
