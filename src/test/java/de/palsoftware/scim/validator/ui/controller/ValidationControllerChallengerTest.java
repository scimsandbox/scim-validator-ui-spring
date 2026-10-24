package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationHttpExchangeView;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationMgmtUser;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.spec.CapabilityStatus;
import de.palsoftware.scim.validator.ui.model.spec.CapabilitySupportLevel;
import de.palsoftware.scim.validator.ui.model.spec.ColourGradient;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceScorecardView;
import de.palsoftware.scim.validator.ui.model.spec.NormativeBreakdown;
import de.palsoftware.scim.validator.ui.model.spec.RequirementTraceResult;
import de.palsoftware.scim.validator.ui.model.spec.RfcSectionSummary;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.service.ComplianceScoreService;
import de.palsoftware.scim.validator.ui.service.GitHubCompliancePublisherService;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.SpecCatalogService;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = ValidationController.class, excludeAutoConfiguration = {
        OAuth2ClientAutoConfiguration.class,
        OAuth2ClientWebSecurityAutoConfiguration.class,
        SecurityAutoConfiguration.class,
        SecurityFilterAutoConfiguration.class
})
@AutoConfigureMockMvc(addFilters = false)
class ValidationControllerChallengerTest {

    private static final DefaultCsrfToken CSRF_TOKEN = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test-token");
    private static final String USER_EMAIL = "developer@example.com";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private ValidationRunService validationRunService;

    @MockitoBean
    private MgmtUserService mgmtUserService;

    @MockitoBean
    private ValidationProgressTracker validationProgressTracker;

    @MockitoBean
    private ComplianceScoreService complianceScoreService;

    @MockitoBean
    private SpecCatalogService specCatalogService;

    @MockitoBean
    private GitHubCompliancePublisherService gitHubCompliancePublisherService;

    @MockitoBean
    private ValidationRunPublicationRepository publicationRepository;

    // ─────────────────────────────────────────────────────────────────────────
    // Dimension 1: Null-Safety & Legacy Compatibility
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("detail: Legacy/aborted run where scorecard is null renders cleanly without crashing")
    void detail_withNullScorecard_rendersGracefully() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(null);
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Compliance Run Result")))
                .andExpect(content().string(containsString(runId.toString())))
                // Scorecard card, ineligibility banner, and publish button must NOT be present
                .andExpect(content().string(not(containsString("SCIM 2.0 Compliance Scorecard"))))
                .andExpect(content().string(not(containsString("Not Eligible for Directory Publication"))))
                .andExpect(content().string(not(containsString("id=\"open-publish-modal-btn\""))))
                .andExpect(content().string(not(containsString("Published on scimsandbox.net Compliance Directory"))));
    }

    @Test
    @DisplayName("detail: Unpublished run with publication=null shows Publish to Directory action and modal")
    void detail_withNullPublication_showsPublishActionAndModal() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");
        ComplianceScorecardView scorecard = createScorecard(runId, 92, true, null);

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Publish to Directory")))
                .andExpect(content().string(containsString("id=\"open-publish-modal-btn\"")))
                .andExpect(content().string(containsString("id=\"publish-modal-overlay\"")))
                .andExpect(content().string(not(containsString("Published on scimsandbox.net Compliance Directory"))));
    }

    @Test
    @DisplayName("detail: Published run renders Published banner, public report link, PR link, and copy badge snippet")
    void detail_withPublishedRun_showsPublishedBannerAndEmbedSnippet() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");
        ValidationRunPublication publication = createSamplePublication(runId, USER_EMAIL, "Published SCIM App", "published-scim-app", 95);
        runEntity.setPublication(publication);
        ComplianceScorecardView scorecard = createScorecard(runId, 95, true, null);

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.of(publication));
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Published on scimsandbox.net Compliance Directory")))
                .andExpect(content().string(containsString("View on Directory ↗")))
                .andExpect(content().string(containsString("View Public Report")))
                .andExpect(content().string(containsString("GitHub Pull Request")))
                .andExpect(content().string(containsString("id=\"copy-badge-markdown-btn\"")))
                .andExpect(content().string(not(containsString("id=\"open-publish-modal-btn\""))));
    }

    @Test
    @DisplayName("index: Empty published runs renders placeholder row and quota 0/50")
    void index_withEmptyPublishedRuns_rendersZeroQuotaAndEmptyNotice() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(0L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(0L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("0 / 50")))
                .andExpect(content().string(containsString("id=\"no-published-runs-row\"")))
                .andExpect(content().string(containsString("No compliance runs published yet")))
                .andExpect(content().string(containsString("Permanent Directory Records:")));
    }

    @Test
    @DisplayName("index: 50 published runs render with danger banner and copy badge snippets")
    void index_withFiftyPublishedRuns_rendersAllFiftyRowsAndBadgeButtons() throws Exception {
        List<ValidationRunPublication> pubs = new ArrayList<>();
        for (int i = 1; i <= 50; i++) {
            pubs.add(createSamplePublication(UUID.randomUUID(), USER_EMAIL, "Product " + i, "product-" + i, 80 + (i % 20)));
        }

        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(pubs);
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(50L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("50 / 50")))
                .andExpect(content().string(containsString("Publication Cap Reached:")))
                .andExpect(content().string(containsString("Product 1")))
                .andExpect(content().string(containsString("Product 50")))
                .andExpect(content().string(containsString("btn-copy-badge-table")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dimension 2: Quota Edge Conditions (0, 44, 45, 49, 50, 55)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("index: Quota at 44 renders info banner, no warning, no danger banner")
    void index_quotaAt44_rendersInfoBannerOnly() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(44L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("44 / 50")))
                .andExpect(content().string(containsString("Permanent Directory Records:")))
                .andExpect(content().string(not(containsString("Approaching Publication Cap:"))))
                .andExpect(content().string(not(containsString("Publication Cap Reached:"))));
    }

    @Test
    @DisplayName("index: Quota at 45 (threshold) renders warning banner with 5 slots remaining")
    void index_quotaAt45_rendersWarningBanner() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(45L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("45 / 50")))
                .andExpect(content().string(containsString("Approaching Publication Cap:")))
                .andExpect(content().string(containsString("5</span> slots remaining")))
                .andExpect(content().string(not(containsString("Permanent Directory Records:"))))
                .andExpect(content().string(not(containsString("Publication Cap Reached:"))));
    }

    @Test
    @DisplayName("index: Quota at 49 renders warning banner with 1 slot remaining")
    void index_quotaAt49_rendersWarningBanner() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(49L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("49 / 50")))
                .andExpect(content().string(containsString("Approaching Publication Cap:")))
                .andExpect(content().string(containsString("1</span> slots remaining")))
                .andExpect(content().string(not(containsString("Permanent Directory Records:"))))
                .andExpect(content().string(not(containsString("Publication Cap Reached:"))));
    }

    @Test
    @DisplayName("index: Quota at 50 (danger cap) renders danger banner")
    void index_quotaAt50_rendersDangerBanner() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(50L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("50 / 50")))
                .andExpect(content().string(containsString("Publication Cap Reached:")))
                .andExpect(content().string(not(containsString("Approaching Publication Cap:"))))
                .andExpect(content().string(not(containsString("Permanent Directory Records:"))));
    }

    @Test
    @DisplayName("index: Quota > 50 (e.g. 55) renders danger banner")
    void index_quotaAt55_rendersDangerBanner() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(5L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(55L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("55 / 50")))
                .andExpect(content().string(containsString("Publication Cap Reached:")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dimension 3: Boundary Values in run-detail.html (0%, 100%, Empty Caps, XSS)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("detail: Scorecard with 0% score renders RED gradient, ineligibility banner, disabled button")
    void detail_withScoreZero_redGradientAndIneligibleBanner() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "FAILED");
        ValidationRun runEntity = createSampleRunEntity(runId, "FAILED");
        ComplianceScorecardView scorecard = createScorecard(runId, 0, false, "Core RFC Conformance (0%) is below the minimum 50% publishing threshold");

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(false);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("0%")))
                .andExpect(content().string(containsString("gradient-red")))
                .andExpect(content().string(containsString("glow-red")))
                .andExpect(content().string(containsString("Not Eligible for Directory Publication")))
                .andExpect(content().string(containsString("class=\"btn-publish-disabled\"")))
                .andExpect(content().string(containsString("Core RFC Conformance (0%) is below the minimum 50% publishing threshold")));
    }

    @Test
    @DisplayName("detail: Scorecard with 100% score renders EMERALD gradient, active publish button, no ineligibility banner")
    void detail_withScoreHundred_emeraldGradientAndEligible() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");
        ComplianceScorecardView scorecard = createScorecard(runId, 100, true, null);

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("100%")))
                .andExpect(content().string(containsString("gradient-emerald")))
                .andExpect(content().string(containsString("glow-emerald")))
                .andExpect(content().string(containsString("btn-publish-action")))
                .andExpect(content().string(not(containsString("Not Eligible for Directory Publication"))))
                .andExpect(content().string(not(containsString("class=\"btn-publish-disabled\""))));
    }

    @Test
    @DisplayName("detail: Scorecard with empty optional capabilities list renders cleanly without crashing")
    void detail_withEmptyOptionalCapabilities_rendersGracefully() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");

        ComplianceScorecardView scorecard = new ComplianceScorecardView(
                runId, "Sample Validation", "https://scim.example.com", OffsetDateTime.now(ZoneOffset.UTC), "PASSED",
                75, ColourGradient.AMBER, true, null,
                NormativeBreakdown.of("MUST", 3, 10, 10, 0, 0, 30.0, 30.0),
                NormativeBreakdown.of("SHOULD", 2, 5, 5, 0, 0, 10.0, 10.0),
                NormativeBreakdown.of("MAY", 1, 2, 2, 0, 0, 2.0, 2.0),
                Collections.emptyList(), 0, 0, 10,
                157, 17, 0, 140,
                Collections.emptyMap(), Collections.emptyList()
        );

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("75%")))
                .andExpect(content().string(containsString("gradient-amber")))
                .andExpect(content().string(not(containsString("class=\"capability-tile\""))));
    }

    @Test
    @DisplayName("detail: Special characters (<>&\"' and Unicode) in product, vendor, and test results are properly escaped")
    void detail_withSpecialCharactersAndXss_safelyEscaped() throws Exception {
        UUID runId = UUID.randomUUID();
        String xssProductName = "<script>alert('xss-product')</script> & \"Quotes\" 'Apos' 日本語 🚀";
        String xssVendor = "<img src=x onerror=alert('vendor')>";
        String xssTestName = "<b style=\"color:red\">Bold Test</b> & 'special'";
        String xssError = "Failed <tag> & \"value\"";

        ValidationRunView runView = new ValidationRunView(
                runId, xssProductName, "https://example.test", OffsetDateTime.now(ZoneOffset.UTC),
                "FAILED", USER_EMAIL, 1, 0, 1
        );
        ValidationRun runEntity = createSampleRunEntity(runId, "FAILED");
        runEntity.setName(xssProductName);

        ValidationTestResultView testView = new ValidationTestResultView(
                UUID.randomUUID(), "specs.XssSpec", "test_01", xssTestName, "FAILED",
                xssError, "Stack trace with <angle-brackets>",
                OffsetDateTime.now(ZoneOffset.UTC), OffsetDateTime.now(ZoneOffset.UTC),
                List.of(new ValidationHttpExchangeView(
                        UUID.randomUUID(), 1, "GET", "https://example.test/scim/v2/Users?filter=name+eq+%22<foo>%22",
                        "Content-Type: application/scim+json", "{\"test\": \"<body & value>\"}",
                        200, "Content-Type: application/json", "{\"res\": \"<script>\"}",
                        OffsetDateTime.now(ZoneOffset.UTC)
                ))
        );

        ValidationRunPublication publication = new ValidationRunPublication();
        publication.setRunId(runId);
        publication.setProductName(xssProductName);
        publication.setProductSlug("xss-product");
        publication.setProductVersion("1.0.0");
        publication.setVendorName(xssVendor);
        publication.setLicenseType("Apache-2.0");
        publication.setCoreScore(45);
        publication.setSupportedCapabilities(5);
        publication.setTotalCapabilities(10);
        publication.setReportUrl("https://scimsandbox.net/compliance/?run=" + runId);
        publication.setBadgeUrl("https://scimsandbox.net/compliance/badges/" + runId + ".svg");
        publication.setPrUrl("https://github.com/scimsandbox/scim-website/pull/1");
        publication.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
        runEntity.setPublication(publication);

        ComplianceScorecardView scorecard = createScorecard(runId, 45, false, "Score below 50%");

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of(testView));
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(false);
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andReturn();

        String html = result.getResponse().getContentAsString();

        // 1. Raw executable script tags from product name must NOT exist unescaped
        assertThat(html).doesNotContain("<script>alert('xss-product')</script>");
        assertThat(html).contains("&lt;script&gt;alert(&#39;xss-product&#39;)&lt;/script&gt;");

        // 2. Raw img onerror tag from vendor name must NOT exist unescaped
        assertThat(html).doesNotContain("<img src=x onerror=alert('vendor')>");
        assertThat(html).contains("&lt;img src=x onerror=alert(&#39;vendor&#39;)&gt;");

        // 3. Raw html in test name must NOT exist unescaped
        assertThat(html).doesNotContain("<b style=\"color:red\">Bold Test</b>");
        assertThat(html).contains("&lt;b style=&quot;color:red&quot;&gt;Bold Test&lt;/b&gt;");

        // 4. Unicode characters and emojis must render cleanly
        assertThat(html).contains("日本語 🚀");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dimension 4: SpecRef Mapping Linking
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("detail: Test item with no @SpecRef annotation renders cleanly without broken badge links")
    void detail_specRefLinking_noSpecRefs_rendersCleanly() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");
        ComplianceScorecardView scorecard = createScorecard(runId, 90, true, null);

        ValidationTestResultView testView = new ValidationTestResultView(
                UUID.randomUUID(), "specs.CustomSpec", "custom_01", "Custom Test without RFC mapping", "SUCCESS",
                null, null, OffsetDateTime.now(ZoneOffset.UTC), OffsetDateTime.now(ZoneOffset.UTC), List.of()
        );

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of(testView));
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of());
        when(specCatalogService.getAllMappings()).thenReturn(List.of());

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Custom Test without RFC mapping")))
                .andExpect(content().string(not(containsString("class=\"specref-badge-pill\""))));
    }

    @Test
    @DisplayName("detail: Test item with multiple @SpecRef annotations renders multiple badge pills linking to matrix")
    void detail_specRefLinking_multipleSpecRefs_rendersMultiplePillLinks() throws Exception {
        UUID runId = UUID.randomUUID();
        ValidationRunView runView = createSampleRunView(runId, "PASSED");
        ValidationRun runEntity = createSampleRunEntity(runId, "PASSED");
        ComplianceScorecardView scorecard = createScorecard(runId, 95, true, null);

        ValidationTestResultView testView = new ValidationTestResultView(
                UUID.randomUUID(), "specs.A1_ServiceDiscoverySpec", "DSC_01",
                "DSC_01: ServiceProviderConfig response is valid",
                "SUCCESS", null, null, OffsetDateTime.now(ZoneOffset.UTC), OffsetDateTime.now(ZoneOffset.UTC), List.of()
        );

        TestSpecMapping multiMapping = new TestSpecMapping(
                "DSC_01", "ServiceProviderConfig response is valid",
                "specs.A1_ServiceDiscoverySpec", "none",
                List.of("RFC7644-4-R1", "RFC7643-3-R2")
        );

        when(validationRunService.getRun(eq(runId), anyString(), anyBoolean())).thenReturn(runView);
        when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of(testView));
        when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
        when(validationRunService.getRawTestResults(runId)).thenReturn(List.of());
        when(validationRunService.getRawExchanges(runId)).thenReturn(List.of());
        when(complianceScoreService.computeScorecard(any(), any(), any())).thenReturn(scorecard);
        when(complianceScoreService.isEligibleForPublish(scorecard, runEntity)).thenReturn(true);
        when(publicationRepository.findById(runId)).thenReturn(Optional.empty());
        when(specCatalogService.getAllTestMappings()).thenReturn(Map.of("DSC_01", multiMapping));
        when(specCatalogService.getAllMappings()).thenReturn(List.of(multiMapping));

        mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("href=\"#req-RFC7644-4-R1\"")))
                .andExpect(content().string(containsString("href=\"#req-RFC7643-3-R2\"")))
                .andExpect(content().string(containsString("RFC7644-4-R1</a>")))
                .andExpect(content().string(containsString("RFC7643-3-R2</a>")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dimension 5: DOM Structure Stress-Testing (Detecting Unclosed run-overlay)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("index: EMPIRICAL STRESS TEST - published-runs-card must NOT be nested inside #run-overlay")
    void index_domStructure_publishedRunsCardMustNotBeNestedInsideOverlay() throws Exception {
        when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedRuns(anyString())).thenReturn(0L);
        when(validationRunService.listPublishedRuns(anyString(), anyBoolean())).thenReturn(List.of());
        when(validationRunService.countOwnedPublications(anyString())).thenReturn(0L);
        when(validationRunService.getMaxPublishedRunsPerUser()).thenReturn(50);

        MvcResult result = mockMvc.perform(get("/validator-ui/")
                        .contextPath("/validator-ui")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken(USER_EMAIL, "n/a")))
                .andExpect(status().isOk())
                .andReturn();

        String html = result.getResponse().getContentAsString();

        // 1. Locate #run-overlay
        int overlayStart = html.indexOf("id=\"run-overlay\"");
        assertThat(overlayStart).as("#run-overlay should exist in index.html").isGreaterThan(0);

        // 2. Locate .published-runs-card
        int cardStart = html.indexOf("class=\"card published-runs-card\"");
        assertThat(cardStart).as(".published-runs-card should exist in index.html").isGreaterThan(0);

        // 3. Locate the end of run-dialog
        int runDialogStart = html.indexOf("class=\"run-dialog\"", overlayStart);
        int progressErrorContainer = html.indexOf("id=\"progress-error-container\"", runDialogStart);

        // Count div closures between progress-error-container and published-runs-card:
        // Level inside progress-error-container:
        // <div id="progress-error-container"> ... </div> (closure 1)
        // </div> (closure 2: closes run-dialog)
        // </div> (closure 3: closes run-overlay) <-- MUST exist before class="card published-runs-card"
        String segmentBetween = html.substring(progressErrorContainer, cardStart);
        int divCloseCount = countOccurrences(segmentBetween, "</div>");

        // If divCloseCount < 3, then run-overlay was NOT closed before published-runs-card!
        assertThat(divCloseCount)
                .as("DOM Hierarchy Failure: #run-overlay was NOT closed before .published-runs-card! " +
                    "There must be at least 3 '</div>' tags between #progress-error-container and .published-runs-card " +
                    "(closing #progress-error-container, .run-dialog, and #run-overlay). " +
                    "Because a closing div is missing, both .published-runs-card and the runs table are hidden inside #run-overlay!")
                .isGreaterThanOrEqualTo(3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Methods
    // ─────────────────────────────────────────────────────────────────────────

    private static int countOccurrences(String text, String sub) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(sub, idx)) != -1) {
            count++;
            idx += sub.length();
        }
        return count;
    }

    private ValidationRunView createSampleRunView(UUID runId, String status) {
        return new ValidationRunView(
                runId,
                "Sample Validation",
                "https://scim.example.com",
                OffsetDateTime.now(ZoneOffset.UTC),
                status,
                USER_EMAIL,
                50,
                status.equals("PASSED") ? 50 : 0,
                status.equals("PASSED") ? 0 : 50
        );
    }

    private ValidationRun createSampleRunEntity(UUID runId, String status) {
        ValidationRun run = new ValidationRun();
        org.springframework.test.util.ReflectionTestUtils.setField(run, "id", runId);
        run.setName("Sample Validation");
        run.setTargetUrl("https://scim.example.com");
        run.setStatus(status);
        run.setTotalTests(50);
        run.setPassedTests(status.equals("PASSED") ? 50 : 0);
        run.setFailedTests(status.equals("PASSED") ? 0 : 50);
        run.setExecutedAt(OffsetDateTime.now(ZoneOffset.UTC));
        ValidationMgmtUser user = new ValidationMgmtUser(USER_EMAIL, OffsetDateTime.now(ZoneOffset.UTC));
        run.setCreatedByUser(user);
        return run;
    }

    private ValidationRunPublication createSamplePublication(UUID runId, String userEmail, String prodName, String prodSlug, int score) {
        ValidationRunPublication pub = new ValidationRunPublication();
        pub.setRunId(runId);
        pub.setCreatedByEmail(userEmail);
        pub.setProductName(prodName);
        pub.setProductSlug(prodSlug);
        pub.setProductVersion("1.0.0");
        pub.setVendorName("Acme Corp");
        pub.setLicenseType("Apache-2.0");
        pub.setShowSubmitter(false);
        pub.setCoreScore(score);
        pub.setSupportedCapabilities(8);
        pub.setTotalCapabilities(10);
        pub.setReportUrl("https://scimsandbox.net/compliance/?run=" + runId);
        pub.setBadgeUrl("https://scimsandbox.net/compliance/badges/" + runId + ".svg");
        pub.setPrUrl("https://github.com/scimsandbox/scim-website/pull/1");
        pub.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return pub;
    }

    private ComplianceScorecardView createScorecard(UUID runId, int score, boolean eligible, String reason) {
        ColourGradient gradient = ColourGradient.forScore(score);
        NormativeBreakdown must = NormativeBreakdown.of("MUST", 3, 134, score > 0 ? 134 : 0, 0, score > 0 ? 0 : 134, score > 0 ? 402.0 : 0.0, 402.0);
        NormativeBreakdown should = NormativeBreakdown.of("SHOULD", 2, 9, score > 0 ? 9 : 0, 0, score > 0 ? 0 : 9, score > 0 ? 18.0 : 0.0, 18.0);
        NormativeBreakdown may = NormativeBreakdown.of("MAY", 1, 4, score > 0 ? 4 : 0, 0, score > 0 ? 0 : 4, score > 0 ? 4.0 : 0.0, 4.0);

        List<CapabilityStatus> caps = List.of(
                CapabilityStatus.of("patch", "PATCH Operations", "RFC 7644 §3.5.2",
                        score > 0 ? CapabilitySupportLevel.SUPPORTED_COMPLIANT : CapabilitySupportLevel.UNSUPPORTED,
                        31, score > 0 ? 31 : 0, score > 0 ? 31 : 0, 0, score > 0 ? 0 : 31)
        );

        List<RequirementTraceResult> matrix = List.of(
                new RequirementTraceResult(
                        "RFC7644-4-R1", "7644", "4", "Service providers MUST support discovery",
                        "MUST", 3, "none", true, 1, 1, score > 0 ? 1 : 0, score > 0 ? 0 : 1, 0,
                        score > 0 ? 3.0 : 0.0, score > 0 ? "COMPLIANT" : "FAILED", List.of("DSC_01")
                )
        );

        return new ComplianceScorecardView(
                runId, "Sample Validation", "https://scim.example.com", OffsetDateTime.now(ZoneOffset.UTC),
                eligible ? "PASSED" : "FAILED", score, gradient, eligible, reason,
                must, should, may, caps, 1, score > 0 ? 1 : 0, 10,
                157, 147, 0, 10,
                Map.of("7644", new RfcSectionSummary("7644", "Protocol", 96, 96, score > 0 ? 96 : 0, score > 0 ? 280.0 : 0.0, 280.0, score)),
                matrix
        );
    }
}
