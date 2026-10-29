package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.spec.ColourGradient;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceScorecardView;
import de.palsoftware.scim.validator.ui.model.spec.NormativeBreakdown;
import de.palsoftware.scim.validator.ui.model.spec.RequirementTraceResult;
import de.palsoftware.scim.validator.ui.service.ComplianceScoreService;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

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
class ValidationControllerTemplateTest {

        private static final DefaultCsrfToken CSRF_TOKEN = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test-token");

        @Autowired
        private MockMvc mockMvc;

        @MockitoBean
        private ValidationRunService validationRunService;

        @MockitoBean
        private MgmtUserService mgmtUserService;

        @MockitoBean
        private de.palsoftware.scim.validator.ui.service.ValidationProgressTracker validationProgressTracker;

        @MockitoBean
        private ComplianceScoreService complianceScoreService;

        @Test
        void indexUsesContextAwareCreateRunAction() throws Exception {
                when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());

                mockMvc.perform(get("/validator-ui/")
                                .contextPath("/validator-ui")
                                .requestAttr("_csrf", CSRF_TOKEN)
                                .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                                .andExpect(status().isOk())
                                .andExpect(content().string(org.hamcrest.Matchers
                                                .containsString("action=\"/validator-ui/runs\"")));
        }

        @Test
        void indexRendersShowOtherUsersCheckboxForAdmin() throws Exception {
                when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());
                when(validationRunService.countOwnedRuns(anyString())).thenReturn(3L);

                var adminToken = new TestingAuthenticationToken("admin@example.com", "n/a",
                                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));

                mockMvc.perform(get("/validator-ui/")
                                .contextPath("/validator-ui")
                                .requestAttr("_csrf", CSRF_TOKEN)
                                .principal(adminToken))
                                .andExpect(status().isOk())
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("id=\"toggle-other-runs\"")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("Show runs from other users")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("data-runs-count=\"3\"")));
        }

        @Test
        void indexDoesNotRenderShowOtherUsersCheckboxForRegularUser() throws Exception {
                when(validationRunService.listRuns(anyString(), anyBoolean())).thenReturn(List.of());

                var userToken = new TestingAuthenticationToken("user@example.com", "n/a",
                                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));

                mockMvc.perform(get("/validator-ui/")
                                .contextPath("/validator-ui")
                                .requestAttr("_csrf", CSRF_TOKEN)
                                .principal(userToken))
                                .andExpect(status().isOk())
                                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                                                .string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("id=\"toggle-other-runs\""))));
        }

        @Test
        void detailUsesContextAwareBackLink() throws Exception {
                UUID runId = UUID.randomUUID();
                when(validationRunService.getRun(eq(runId), anyString(), anyBoolean()))
                                .thenReturn(new ValidationRunView(
                                                runId,
                                                "Nightly validation",
                                                "https://example.test/scim/v2",
                                                OffsetDateTime.parse("2026-03-14T12:00:00Z"),
                                                "PASSED",
                                                "user@example.com",
                                                10,
                                                10,
                                                0));
                when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());

                mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                                .contextPath("/validator-ui")
                                .requestAttr("_csrf", CSRF_TOKEN)
                                .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                                .andExpect(status().isOk())
                                .andExpect(content().string(
                                                org.hamcrest.Matchers.containsString("href=\"/validator-ui/\"")));
        }

        @Test
        void detailRendersClickableRfcSectionLinksInRequirementMatrix() throws Exception {
                UUID runId = UUID.randomUUID();
                ValidationRun runEntity = new ValidationRun();
                runEntity.setName("RFC Link Test Run");
                runEntity.setStatus("PASSED");

                when(validationRunService.getRun(eq(runId), anyString(), anyBoolean()))
                                .thenReturn(new ValidationRunView(
                                                runId,
                                                "RFC Link Test Run",
                                                "https://example.test/scim/v2",
                                                OffsetDateTime.parse("2026-03-14T12:00:00Z"),
                                                "PASSED",
                                                "user@example.com",
                                                1,
                                                1,
                                                0));
                when(validationRunService.getTestResults(eq(runId), anyString(), anyBoolean())).thenReturn(List.of());
                when(validationRunService.getRunEntity(eq(runId), anyString(), anyBoolean())).thenReturn(runEntity);
                when(validationRunService.getRawTestResults(eq(runId))).thenReturn(List.of());
                when(validationRunService.getRawExchanges(eq(runId))).thenReturn(List.of());

                RequirementTraceResult trace = new RequirementTraceResult(
                                "RFC7644-4-R1",
                                "7644",
                                "4",
                                "GET /ServiceProviderConfig returns HTTP 200",
                                "MUST",
                                3,
                                "none",
                                true,
                                1,
                                1,
                                1,
                                0,
                                0,
                                3.0,
                                "COMPLIANT",
                                List.of("DSC_01"));
                RequirementTraceResult optTrace = new RequirementTraceResult(
                                "RFC9967-4-R1",
                                "9967",
                                "4",
                                "Asynchronous request processing with 202 Accepted",
                                "OPTIONAL",
                                1,
                                "async",
                                true,
                                1,
                                1,
                                1,
                                0,
                                0,
                                1.0,
                                "COMPLIANT",
                                List.of("ASY_01"));
                NormativeBreakdown breakdown = new NormativeBreakdown("MUST", 3, 1, 1, 0, 0, 3.0, 3.0, 100);
                NormativeBreakdown emptyBreakdown = new NormativeBreakdown("SHOULD", 2, 0, 0, 0, 0, 0.0, 0.0, 100);
                NormativeBreakdown optBreakdown = new NormativeBreakdown("OPTIONAL", 1, 1, 1, 0, 0, 1.0, 1.0, 100);
                ComplianceScorecardView scorecard = new ComplianceScorecardView(
                                runId,
                                "RFC Link Test Run",
                                "https://example.test/scim/v2",
                                OffsetDateTime.parse("2026-03-14T12:00:00Z"),
                                "PASSED",
                                100,
                                ColourGradient.EMERALD,
                                true,
                                null,
                                breakdown,
                                emptyBreakdown,
                                optBreakdown,
                                List.of(),
                                0,
                                0,
                                10,
                                159,
                                157,
                                2,
                                0,
                                java.util.Map.of(),
                                List.of(trace, optTrace));
                when(complianceScoreService.computeScorecard(eq(runEntity), eq(List.of()), eq(List.of())))
                                .thenReturn(scorecard);

                mockMvc.perform(get("/validator-ui/runs/{runId}", runId)
                                .contextPath("/validator-ui")
                                .requestAttr("_csrf", CSRF_TOKEN)
                                .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                                .andExpect(status().isOk())
                                .andExpect(content().string(org.hamcrest.Matchers.containsString(
                                                "href=\"https://www.rfc-editor.org/rfc/rfc7644#section-4\"")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("class=\"req-rfc-link\"")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("target=\"_blank\"")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("rel=\"noopener noreferrer\"")))
                                .andExpect(content().string(org.hamcrest.Matchers.containsString("normative-tag optional")));
        }
}