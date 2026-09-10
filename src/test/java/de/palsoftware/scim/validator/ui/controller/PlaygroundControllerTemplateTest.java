package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.PlaygroundExecutionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.hamcrest.Matchers.matchesRegex;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = PlaygroundController.class, excludeAutoConfiguration = {
        OAuth2ClientAutoConfiguration.class,
        OAuth2ClientWebSecurityAutoConfiguration.class,
        SecurityAutoConfiguration.class,
        SecurityFilterAutoConfiguration.class
})
@AutoConfigureMockMvc(addFilters = false)
class PlaygroundControllerTemplateTest {

    private static final DefaultCsrfToken CSRF_TOKEN = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test-token");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private PlaygroundExecutionService playgroundExecutionService;

    @MockitoBean
    private MgmtUserService mgmtUserService;

    @Test
    void playgroundRoot_redirectsToUsers() throws Exception {
        mockMvc.perform(get("/playground")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/playground/users"));
    }

    @Test
    void executeRequest_blankFields_returnValidationMessagesInErrorField() throws Exception {
        mockMvc.perform(post("/api/playground/execute")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"baseUrl\":\"\",\"method\":\"\",\"endpoint\":\"\"}")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Base URL is required")))
                .andExpect(content().string(containsString("HTTP Method is required")))
                .andExpect(content().string(containsString("Endpoint path is required")));
    }

    @Test
    void executeRequest_malformedJson_returnsReadableError() throws Exception {
        mockMvc.perform(post("/api/playground/execute")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ not json")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Malformed request body")));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "users",
            "groups",
            "resource-types",
            "schemas",
            "service-provider-config",
            "bulk",
            "search",
            "etag"
    })
    void playgroundTopics_renderSuccessfully(String topic) throws Exception {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        mockMvc.perform(get("/playground/" + topic)
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(">SCIM Validation</h1>")))
                // Both nav segments carry their product names, and this page is the active one.
                .andExpect(content().string(containsString(">SCIM Compliance</span>")))
                .andExpect(content().string(containsString(">SCIM Playground</span>")))
                .andExpect(content().string(containsString("nav-segment active")))
                .andExpect(content().string(containsString("Active SCIM Server Target")))
                // the sidebar link for the requested topic exists...
                .andExpect(content().string(containsString("href=\"/playground/" + topic + "\"")))
                // ...and exactly one link is marked active
                .andExpect(content().string(matchesRegex("(?s).*sidebar-link active.*")))
                // Model-driven user chip rendered as element TEXT. Asserting the bare string is not
                // enough: Thymeleaf turns an unrecognised th:* attribute (a typo such as th:txet)
                // into a plain attribute carrying the evaluated value, so the text would still
                // appear in the markup while the element itself still shows its static placeholder.
                .andExpect(content().string(containsString(">Alex Morgan (User)<")))
                .andExpect(content().string(not(containsString(">User (Role)<"))))
                // Footer and BMC widget
                .andExpect(content().string(containsString("<footer class=\"site-footer\">")))
                // The side-dock link OUT to the server management UI. Asserting the bare product
                // name is not enough here: "SCIM Playground" is now this page's own nav label, so a
                // loose match would keep passing even if the outbound link were mislabelled.
                .andExpect(content().string(containsString("aria-label=\"SCIM Server Manager\"")))
                .andExpect(content().string(containsString("Terms of Service")))
                .andExpect(content().string(containsString("Privacy Policy")))
                .andExpect(content().string(containsString("bmc-widget")));
    }

    @Test
    void playgroundTopic_marksExactlyOneSidebarLinkActive() throws Exception {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        String html = mockMvc.perform(get("/playground/groups")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String body = html.substring(html.indexOf("<body>"));
        int active = body.split("sidebar-link active", -1).length - 1;
        org.assertj.core.api.Assertions.assertThat(active)
                .as("exactly one sidebar link should carry the active class")
                .isEqualTo(1);
    }

    @Test
    void playgroundTopic_operationHeadersAreKeyboardOperable() throws Exception {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        String html = mockMvc.perform(get("/playground/users")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String body = html.substring(html.indexOf("<body>"));
        int heads = body.split("class=\"op-head\"", -1).length - 1;
        int operable = body.split("class=\"op-head\" role=\"button\" tabindex=\"0\" aria-expanded=", -1).length - 1;

        org.assertj.core.api.Assertions.assertThat(heads)
                .as("the users topic should render operation headers")
                .isGreaterThan(0);
        org.assertj.core.api.Assertions.assertThat(operable)
                .as("every operation header must be focusable and expose aria-expanded, "
                        + "otherwise the accordion cannot be opened without a mouse")
                .isEqualTo(heads);
    }

    @Test
    void playgroundTopic_externalLinksCarryNoopener() throws Exception {
        when(mgmtUserService.resolveDisplayName(anyString(), anyString())).thenReturn("Alex Morgan");

        String html = mockMvc.perform(get("/playground/users")
                        .requestAttr("_csrf", CSRF_TOKEN)
                        .principal(new TestingAuthenticationToken("user@example.com", "n/a")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String body = html.substring(html.indexOf("<body>"));
        java.util.regex.Matcher anchors = java.util.regex.Pattern.compile("<a\\b[^>]*>").matcher(body);
        java.util.List<String> unsafe = new java.util.ArrayList<>();
        while (anchors.find()) {
            String tag = anchors.group();
            if (tag.contains("target=\"_blank\"") && !tag.contains("rel=")) {
                unsafe.add(tag);
            }
        }

        org.assertj.core.api.Assertions.assertThat(unsafe)
                .as("every target=_blank link needs rel=noopener to avoid handing the opener to the target page")
                .isEmpty();
    }
}
