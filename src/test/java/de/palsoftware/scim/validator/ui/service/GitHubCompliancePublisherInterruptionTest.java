package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GitHubCompliancePublisherInterruptionTest {

    @AfterEach
    void clearInterruptFlag() {
        Thread.interrupted();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5, 6, 7, 8, 9})
    @SuppressWarnings("unchecked")
    void publish_whenInterruptedAtSteps1Through9_restoresInterruptFlagAndFailsCleanly(int interruptStep) throws Exception {
        GitHubAuthService authService = mock(GitHubAuthService.class);
        when(authService.getInstallationAccessToken()).thenReturn("ghs_test_token");

        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest req = invocation.getArgument(0);
                    int step = classifyStep(req);
                    if (step == interruptStep) {
                        throw new InterruptedException("simulated interrupt at step " + step);
                    }
                    return buildSuccessResponse(step);
                });

        GitHubCompliancePublisherService service = createConfiguredService(authService, httpClient);
        CompliancePublishRequest request = buildSampleRequest();

        assertThatThrownBy(() -> service.publish(request))
                .isInstanceOf(RuntimeException.class);
        assertThat(Thread.interrupted()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void publish_whenInterruptedDuringCleanupDeleteBranchRef_restoresInterruptFlagAndStillReturnsSuccess() throws Exception {
        GitHubAuthService authService = mock(GitHubAuthService.class);
        when(authService.getInstallationAccessToken()).thenReturn("ghs_test_token");

        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest req = invocation.getArgument(0);
                    int step = classifyStep(req);
                    if (step == 10) {
                        throw new InterruptedException("simulated interrupt on cleanup delete");
                    }
                    return buildSuccessResponse(step);
                });

        GitHubCompliancePublisherService service = createConfiguredService(authService, httpClient);
        service.setPublicationRepository(mock(ValidationRunPublicationRepository.class));

        CompliancePublicationResult result = service.publish(buildSampleRequest());

        assertThat(result.success()).isTrue();
        assertThat(Thread.interrupted()).isTrue();
    }

    private static GitHubCompliancePublisherService createConfiguredService(
            GitHubAuthService authService,
            HttpClient httpClient) {
        GitHubCompliancePublisherService service = new GitHubCompliancePublisherService(
                authService,
                new ComplianceReportGenerator(),
                new ComplianceBadgeGenerator(),
                new ObjectMapper(),
                httpClient,
                "https://api.github.example"
        );
        service.setEnabled(true);
        service.setRepo("scimsandbox/scim-website");
        service.setBranch("main");
        service.setPublicBaseUrl("https://scimsandbox.net");
        return service;
    }

    private static CompliancePublishRequest buildSampleRequest() {
        return new CompliancePublishRequest(
                UUID.randomUUID(),
                "SCIM Sandbox (Go)",
                "scim-sandbox-go",
                "0.2.11",
                "ScimSandbox Org",
                "https://github.com/scimsandbox/scim-server-go",
                "Apache-2.0",
                true,
                98,
                "EMERALD",
                8,
                10,
                "dev@scimsandbox.net"
        );
    }

    private static int classifyStep(HttpRequest req) {
        String method = req.method();
        String path = req.uri().getPath();
        if ("GET".equals(method) && path.contains("/git/ref/heads/")) {
            return 1;
        }
        if ("GET".equals(method) && path.contains("/git/commits/")) {
            return 2;
        }
        if ("GET".equals(method) && path.contains("/contents/compliance/index.json")) {
            return 3;
        }
        if ("POST".equals(method) && path.endsWith("/git/refs")) {
            return 4;
        }
        if ("POST".equals(method) && path.endsWith("/git/trees")) {
            return 5;
        }
        if ("POST".equals(method) && path.endsWith("/git/commits")) {
            return 6;
        }
        if ("PATCH".equals(method) && path.contains("/git/refs/heads/")) {
            return 7;
        }
        if ("POST".equals(method) && path.endsWith("/pulls")) {
            return 8;
        }
        if ("PUT".equals(method) && path.endsWith("/merge")) {
            return 9;
        }
        if ("DELETE".equals(method) && path.contains("/git/refs/heads/")) {
            return 10;
        }
        throw new IllegalStateException("Unexpected request: " + method + " " + path);
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<String> buildSuccessResponse(int step) {
        HttpResponse<String> response = mock(HttpResponse.class);
        switch (step) {
            case 1 -> {
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn("{\"object\":{\"sha\":\"1111111111111111111111111111111111111111\"}}");
            }
            case 2 -> {
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn("{\"tree\":{\"sha\":\"2222222222222222222222222222222222222222\"}}");
            }
            case 3 -> {
                when(response.statusCode()).thenReturn(404);
                when(response.body()).thenReturn("{}");
            }
            case 4 -> {
                when(response.statusCode()).thenReturn(201);
                when(response.body()).thenReturn("{\"ref\":\"refs/heads/publish/test\"}");
            }
            case 5 -> {
                when(response.statusCode()).thenReturn(201);
                when(response.body()).thenReturn("{\"sha\":\"3333333333333333333333333333333333333333\"}");
            }
            case 6 -> {
                when(response.statusCode()).thenReturn(201);
                when(response.body()).thenReturn("{\"sha\":\"4444444444444444444444444444444444444444\"}");
            }
            case 7 -> {
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn("{\"object\":{\"sha\":\"4444444444444444444444444444444444444444\"}}");
            }
            case 8 -> {
                when(response.statusCode()).thenReturn(201);
                when(response.body()).thenReturn("{\"number\":42,\"html_url\":\"https://github.com/scimsandbox/scim-website/pull/42\"}");
            }
            case 9 -> {
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn("{\"merged\":true,\"sha\":\"5555555555555555555555555555555555555555\"}");
            }
            case 10 -> {
                when(response.statusCode()).thenReturn(204);
                when(response.body()).thenReturn("");
            }
            default -> throw new IllegalStateException("Unexpected step: " + step);
        }
        return response;
    }
}
