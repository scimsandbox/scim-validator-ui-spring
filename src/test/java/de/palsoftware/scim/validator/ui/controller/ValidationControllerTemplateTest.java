package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
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
}