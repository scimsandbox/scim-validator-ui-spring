package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.CompliancePublishFormData;
import de.palsoftware.scim.validator.ui.dto.ValidationProgress;
import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.dto.ValidationTestResultView;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationRunPublication;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublicationResult;
import de.palsoftware.scim.validator.ui.model.spec.CompliancePublishRequest;
import de.palsoftware.scim.validator.ui.model.spec.ComplianceScorecardView;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import de.palsoftware.scim.validator.ui.repo.ValidationRunPublicationRepository;
import de.palsoftware.scim.validator.ui.security.AuthenticatedUser;
import de.palsoftware.scim.validator.ui.security.TargetUrlPolicy;
import de.palsoftware.scim.validator.ui.service.ComplianceScoreService;
import de.palsoftware.scim.validator.ui.service.GitHubCompliancePublisherService;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.SpecCatalogService;
import de.palsoftware.scim.validator.ui.service.ValidationProgressTracker;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ByteArrayResource;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.util.Collections;
import java.util.Locale;
import java.util.UUID;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

@Controller
public class ValidationController {

    private static final Logger log = LoggerFactory.getLogger(ValidationController.class);

    private static final String ATTR_CURRENT_USER = "currentUser";
    private static final String ATTR_CURRENT_USER_ROLE = "currentUserRole";
    private static final String ROLE_ADMIN = "Admin";
    private static final String ROLE_USER = "User";

    private final ValidationRunService validationRunService;
    private final MgmtUserService mgmtUserService;
    private final ValidationProgressTracker validationProgressTracker;
    private final String serverManagerUrl;
    private final ComplianceScoreService complianceScoreService;
    private final SpecCatalogService specCatalogService;
    private final GitHubCompliancePublisherService gitHubCompliancePublisherService;
    private final ValidationRunPublicationRepository publicationRepository;

    public ValidationController(ValidationRunService validationRunService,
            MgmtUserService mgmtUserService,
            ValidationProgressTracker validationProgressTracker,
            @Value("${app.server-manager.url}") String serverManagerUrl) {
        this(validationRunService, mgmtUserService, validationProgressTracker, serverManagerUrl,
                null, null, null, null);
    }

    @Autowired
    public ValidationController(
            ValidationRunService validationRunService,
            MgmtUserService mgmtUserService,
            ValidationProgressTracker validationProgressTracker,
            @Value("${app.server-manager.url}") String serverManagerUrl,
            @Autowired(required = false) ComplianceScoreService complianceScoreService,
            @Autowired(required = false) SpecCatalogService specCatalogService,
            @Autowired(required = false) GitHubCompliancePublisherService gitHubCompliancePublisherService,
            @Autowired(required = false) ValidationRunPublicationRepository publicationRepository) {
        this.validationRunService = validationRunService;
        this.mgmtUserService = mgmtUserService;
        this.validationProgressTracker = validationProgressTracker;
        this.serverManagerUrl = serverManagerUrl;
        this.complianceScoreService = complianceScoreService;
        this.specCatalogService = specCatalogService;
        this.gitHubCompliancePublisherService = gitHubCompliancePublisherService;
        this.publicationRepository = publicationRepository;
    }

    @GetMapping("/")
    public String index(
            @RequestParam(name = "showOthers", required = false) String showOthers,
            Model model,
            Authentication authentication) {
        if (!model.containsAttribute("runForm")) {
            model.addAttribute("runForm", new ValidationRunForm("", "", ""));
        }
        String userEmail = actorEmail(authentication);
        boolean admin = isAdmin(authentication);
        boolean showOthersEnabled = admin && !"false".equalsIgnoreCase(showOthers);
        model.addAttribute("runs", validationRunService.listRuns(userEmail, admin));
        model.addAttribute("myRunsCount", validationRunService.countOwnedRuns(userEmail));
        model.addAttribute("currentUserEmail", userEmail);
        model.addAttribute("isAdmin", admin);
        model.addAttribute("showOthers", showOthersEnabled);
        model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
        model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
        model.addAttribute("maxRuns", validationRunService.getMaxRunsPerUser());
        model.addAttribute("serverManagerUrl", serverManagerUrl);

        populatePublishedRunsModel(model, userEmail, admin, showOthersEnabled);
        return "index";
    }

    private void populatePublishedRunsModel(Model model, String userEmail, boolean admin, boolean showOthersEnabled) {
        boolean queryScopeAdmin = admin && showOthersEnabled;
        List<ValidationRunPublication> publishedRuns = validationRunService != null
                ? validationRunService.listPublishedRuns(userEmail, queryScopeAdmin)
                : List.of();
        long count = validationRunService != null
                ? validationRunService.countOwnedPublications(userEmail)
                : 0L;
        int maxPublished = validationRunService != null
                ? validationRunService.getMaxPublishedRunsPerUser()
                : 50;
        if (maxPublished <= 0) {
            maxPublished = 50;
        }

        model.addAttribute("publishedRuns", publishedRuns);
        model.addAttribute("publishedRunsCount", count);
        model.addAttribute("publishedCount", count);
        model.addAttribute("myPublishedRunsCount", count);
        model.addAttribute("maxPublishedRuns", maxPublished);
        model.addAttribute("publishedQuotaMax", maxPublished);
    }

    @PostMapping(value = "/runs", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<?> executeAsync(
            @Valid @ModelAttribute("runForm") ValidationRunForm runForm,
            BindingResult bindingResult,
            Authentication authentication) {
        if (!bindingResult.hasFieldErrors("baseUrl")) {
            try {
                TargetUrlPolicy.validate(runForm.baseUrl());
            } catch (IllegalArgumentException ex) {
                bindingResult.rejectValue("baseUrl", "baseUrl.invalid", ex.getMessage());
            }
        }
        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));
            return ResponseEntity.badRequest().body(Map.of("errors", errors));
        }

        String userEmail = actorEmail(authentication);
        ValidationRunService.ExecutionResult result = validationRunService.executeRunAsync(runForm, userEmail);
        ValidationRun run = result.getRun();
        Map<String, Object> response = new HashMap<>();
        response.put("runId", run.getId().toString());
        response.put("totalTests", run.getTotalTests());
        response.put("redirectUrl", "/runs/" + run.getId());
        response.put("oldRunDeleted", result.isOldRunDeleted());
        response.put("maxRuns", result.getMaxRuns());
        response.put("myRunsCount", validationRunService.countOwnedRuns(userEmail));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/runs")
    public String execute(@Valid @ModelAttribute("runForm") ValidationRunForm runForm,
            BindingResult bindingResult,
            Model model,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {
        if (!bindingResult.hasFieldErrors("baseUrl")) {
            try {
                TargetUrlPolicy.validate(runForm.baseUrl());
            } catch (IllegalArgumentException ex) {
                bindingResult.rejectValue("baseUrl", "baseUrl.invalid", ex.getMessage());
            }
        }
        if (bindingResult.hasErrors()) {
            String userEmail = actorEmail(authentication);
            boolean admin = isAdmin(authentication);
            model.addAttribute("runs",
                validationRunService.listRuns(userEmail, admin));
            model.addAttribute("myRunsCount", validationRunService.countOwnedRuns(userEmail));
            model.addAttribute("currentUserEmail", userEmail);
            model.addAttribute("isAdmin", admin);
            model.addAttribute("showOthers", true);
            model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
            model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
            model.addAttribute("maxRuns", validationRunService.getMaxRunsPerUser());
            model.addAttribute("serverManagerUrl", serverManagerUrl);
            populatePublishedRunsModel(model, userEmail, admin, true);
            return "index";
        }

        ValidationRunService.ExecutionResult result = validationRunService.executeRun(runForm, actorEmail(authentication));
        ValidationRunView run = ValidationRunView.from(result.getRun(), validationRunService.getReservationTimeout());
        if (result.isOldRunDeleted()) {
            redirectAttributes.addFlashAttribute("infoMessage", 
                "An older test suite was deleted to make room for this new one. Maximum allowed test suites per user is " + result.getMaxRuns() + ".");
        }
        return "redirect:/runs/" + run.id();
    }

    @GetMapping(value = "/runs/{runId}/progress", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public SseEmitter streamProgress(@PathVariable UUID runId, Authentication authentication) {
        validationRunService.getRun(runId, actorEmail(authentication), isAdmin(authentication));
        return validationProgressTracker.subscribe(runId);
    }

    @GetMapping(value = "/runs/{runId}/status", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<ValidationProgress> getStatus(@PathVariable UUID runId, Authentication authentication) {
        ValidationRunView run = validationRunService.getRun(runId, actorEmail(authentication), isAdmin(authentication));
        ValidationProgress progress = validationProgressTracker.getProgress(runId);
        if (progress == null) {
            String status = run.status();
            boolean isTerminal = "PASSED".equals(status) || "FAILED".equals(status);
            progress = new ValidationProgress(
                    run.id(),
                    status,
                    run.totalTests(),
                    run.totalTests(),
                    0,
                    100,
                    run.passedTests(),
                    run.failedTests(),
                    "",
                    isTerminal ? "Validation completed" : status,
                    null,
                    "/runs/" + run.id()
            );
        }
        return ResponseEntity.ok(progress);
    }

    @GetMapping("/runs/{runId}")
    public String detail(@PathVariable UUID runId, Model model, Authentication authentication) {
        String userEmail = actorEmail(authentication);
        boolean admin = isAdmin(authentication);
        ValidationRunView runView = null;
        try {
            runView = validationRunService.getRun(runId, userEmail, admin);
            List<ValidationTestResultView> testViews = validationRunService.getTestResults(runId, userEmail, admin);
            model.addAttribute("run", runView);
            model.addAttribute("tests", testViews);

            ValidationRun runEntity = null;
            try {
                runEntity = validationRunService.getRunEntity(runId, userEmail, admin);
            } catch (Exception e) {
                log.debug("Could not retrieve runEntity for runId={}: {}", runId, e.getMessage());
            }

            ComplianceScorecardView scorecard = null;
            if (complianceScoreService != null && runEntity != null) {
                try {
                    List<ValidationTestResult> rawTests = validationRunService.getRawTestResults(runId);
                    List<ValidationHttpExchange> rawExchanges = validationRunService.getRawExchanges(runId);
                    scorecard = complianceScoreService.computeScorecard(runEntity, rawTests, rawExchanges);
                } catch (Exception e) {
                    log.warn("Failed to compute scorecard for runId={}: {}", runId, e.getMessage());
                }
            }
            model.addAttribute("scorecard", scorecard);

            boolean isEligibleForPublish = false;
            if (complianceScoreService != null && scorecard != null && runEntity != null) {
                try {
                    isEligibleForPublish = complianceScoreService.isEligibleForPublish(scorecard, runEntity);
                } catch (Exception e) {
                    log.debug("Could not determine publish eligibility: {}", e.getMessage());
                }
            }
            model.addAttribute("isEligibleForPublish", isEligibleForPublish);
            model.addAttribute("minPublishScore", complianceScoreService != null
                    ? complianceScoreService.getMinPublishScore()
                    : ComplianceScoreService.DEFAULT_MIN_PUBLISH_SCORE);

            ValidationRunPublication rawPublication = null;
            if (runEntity != null && runEntity.getPublication() != null) {
                rawPublication = runEntity.getPublication();
            } else if (publicationRepository != null) {
                try {
                    rawPublication = publicationRepository.findById(runId).orElse(null);
                } catch (Exception e) {
                    log.debug("Could not retrieve publication from repository: {}", e.getMessage());
                }
            }
            boolean isPendingPublish = rawPublication != null && rawPublication.isPendingReservation()
                    && (validationRunService == null || !validationRunService.isStaleReservation(rawPublication));
            ValidationRunPublication publication = (rawPublication != null && !rawPublication.isPendingReservation())
                    ? rawPublication
                    : null;
            model.addAttribute("publication", publication);
            model.addAttribute("isPublished", publication != null);
            model.addAttribute("isPublishing", isPendingPublish);

            Map<String, TestSpecMapping> testSpecMappings = buildComprehensiveTestMappings();
            model.addAttribute("testSpecMappings", testSpecMappings);

            if (!model.containsAttribute("publishForm")) {
                CompliancePublishFormData publishForm = new CompliancePublishFormData();
                String candidateName = runEntity != null ? runEntity.getName() : (runView != null ? runView.name() : null);
                if (isSafeDefaultProductName(candidateName)) {
                    publishForm.setProductName(candidateName);
                    publishForm.setProductSlug(publishForm.resolveProductSlug());
                } else {
                    publishForm.setProductName("");
                    publishForm.setProductSlug("");
                }
                model.addAttribute("publishForm", publishForm);
            }
        } catch (ResponseStatusException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                model.addAttribute("runNotFound", true);
            } else {
                throw e;
            }
        }
        model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
        model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
        model.addAttribute("serverManagerUrl", serverManagerUrl);
        return "run-detail";
    }

    private static boolean isSafeDefaultProductName(String runName) {
        if (runName == null || runName.isBlank()) {
            return false;
        }
        String lower = runName.toLowerCase();
        if (lower.contains("://") || lower.contains("localhost") || lower.contains("/scim")) {
            return false;
        }
        return !runName.matches(".*\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b.*");
    }

    private Map<String, TestSpecMapping> buildComprehensiveTestMappings() {
        if (specCatalogService == null) {
            return Collections.emptyMap();
        }
        Map<String, TestSpecMapping> combined = new HashMap<>(specCatalogService.getAllTestMappings());
        for (TestSpecMapping mapping : specCatalogService.getAllMappings()) {
            if (mapping.displayName() != null) {
                combined.putIfAbsent(mapping.displayName(), mapping);
            }
        }
        return combined;
    }

    @PostMapping("/runs/{runId}/publish")
    public String publishRun(
            @PathVariable UUID runId,
            @Valid @ModelAttribute("publishForm") CompliancePublishFormData publishForm,
            BindingResult bindingResult,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String userEmail = actorEmail(authentication);
        if (userEmail == null || userEmail.isBlank()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Authentication required to publish compliance report.");
            return "redirect:/runs/" + runId;
        }
        boolean admin = isAdmin(authentication);

        ValidationRun runEntity;
        try {
            runEntity = validationRunService.getRunEntity(runId, userEmail, admin);
        } catch (ResponseStatusException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getReason());
            return "redirect:/";
        }

        if (runEntity.isPublished()) {
            redirectAttributes.addFlashAttribute("errorMessage", "This validation run has already been published to the Compliance Directory.");
            return "redirect:/runs/" + runId;
        }
        if (runEntity.hasPendingReservation()
                && validationRunService != null
                && !validationRunService.isStaleReservation(runEntity.getPublication())) {
            redirectAttributes.addFlashAttribute("errorMessage", "A publication for this validation run is already in progress. Please wait or try again shortly.");
            return "redirect:/runs/" + runId;
        }

        if (bindingResult.hasErrors()) {
            String errorMsg = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining("; "));
            redirectAttributes.addFlashAttribute("errorMessage", "Validation error: " + errorMsg);
            return "redirect:/runs/" + runId;
        }

        String quotaOwnerEmail = (runEntity.getCreatedByEmail() != null && !runEntity.getCreatedByEmail().isBlank())
                ? runEntity.getCreatedByEmail()
                : userEmail;
        String resolvedSlug = publishForm.resolveProductSlug();
        try {
            validationRunService.validatePublishQuota(quotaOwnerEmail);
            validationRunService.validateProductSlugOwnership(resolvedSlug, quotaOwnerEmail);
        } catch (ResponseStatusException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getReason());
            return "redirect:/runs/" + runId;
        }

        String targetUrl = runEntity.getTargetUrl();
        if (targetUrl == null || targetUrl.isBlank()) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Validation error: Validation run is missing a target URL and cannot be verified for sanitization.");
            return "redirect:/runs/" + runId;
        }
        String trimmedTarget = targetUrl.trim();
        if (containsIgnoreCase(publishForm.getProductName(), trimmedTarget)
                || containsIgnoreCase(publishForm.getProductSlug(), trimmedTarget)
                || containsIgnoreCase(resolvedSlug, trimmedTarget)
                || containsIgnoreCase(publishForm.getProductVersion(), trimmedTarget)
                || containsIgnoreCase(publishForm.getVendorName(), trimmedTarget)
                || containsIgnoreCase(publishForm.getLicenseType(), trimmedTarget)
                || containsIgnoreCase(publishForm.getProjectUrl(), trimmedTarget)) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Validation error: Product metadata and Project URL must not contain the validation target URL.");
            return "redirect:/runs/" + runId;
        }
        String targetHost = null;
        try {
            targetHost = URI.create(trimmedTarget).getHost();
        } catch (Exception ignored) {
        }
        if (targetHost != null && !targetHost.isBlank()) {
            String bareTargetHost = (targetHost.startsWith("[") && targetHost.endsWith("]") && targetHost.length() > 2)
                    ? targetHost.substring(1, targetHost.length() - 1)
                    : targetHost;
            if (containsIgnoreCase(publishForm.getProductName(), targetHost)
                    || containsIgnoreCase(publishForm.getProductName(), bareTargetHost)
                    || containsIgnoreCase(publishForm.getProductSlug(), targetHost)
                    || containsIgnoreCase(publishForm.getProductSlug(), bareTargetHost)
                    || containsIgnoreCase(resolvedSlug, targetHost)
                    || containsIgnoreCase(resolvedSlug, bareTargetHost)
                    || containsIgnoreCase(publishForm.getProductVersion(), targetHost)
                    || containsIgnoreCase(publishForm.getProductVersion(), bareTargetHost)
                    || containsIgnoreCase(publishForm.getVendorName(), targetHost)
                    || containsIgnoreCase(publishForm.getVendorName(), bareTargetHost)
                    || containsIgnoreCase(publishForm.getLicenseType(), targetHost)
                    || containsIgnoreCase(publishForm.getLicenseType(), bareTargetHost)) {
                redirectAttributes.addFlashAttribute("errorMessage",
                        "Validation error: Product metadata fields (Product Name, Slug, Version, Vendor, License) must not contain the validation target host (" + targetHost + ").");
                return "redirect:/runs/" + runId;
            }
        }

        List<ValidationTestResult> rawTests = validationRunService.getRawTestResults(runId);
        List<ValidationHttpExchange> rawExchanges = validationRunService.getRawExchanges(runId);
        if (complianceScoreService == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Compliance scoring service is unavailable.");
            return "redirect:/runs/" + runId;
        }

        ComplianceScorecardView scorecard = complianceScoreService.computeScorecard(runEntity, rawTests, rawExchanges);
        if (!complianceScoreService.isEligibleForPublish(scorecard, runEntity)) {
            int minScore = complianceScoreService.getMinPublishScore();
            String reason = scorecard.publishIneligibilityReason() != null
                    ? scorecard.publishIneligibilityReason()
                    : "Run does not meet publishing eligibility criteria (Core Conformance >= " + minScore + "% and terminal status).";
            redirectAttributes.addFlashAttribute("errorMessage", "Publication rejected: " + reason);
            return "redirect:/runs/" + runId;
        }

        CompliancePublishRequest publishRequest = new CompliancePublishRequest(
                runEntity.getId(),
                publishForm.getProductName().trim(),
                resolvedSlug,
                publishForm.getProductVersion().trim(),
                publishForm.getVendorName() != null ? publishForm.getVendorName().trim() : null,
                publishForm.getProjectUrl() != null && !publishForm.getProjectUrl().isBlank() ? publishForm.getProjectUrl().trim() : null,
                publishForm.getLicenseType().trim(),
                publishForm.isShowSubmitter(),
                scorecard.coreScore(),
                scorecard.colourGradient().name(),
                scorecard.supportedCapabilitiesCount(),
                scorecard.totalCapabilitiesCount(),
                userEmail,
                runEntity.getTargetUrl(),
                scorecard
        );

        if (gitHubCompliancePublisherService == null || !gitHubCompliancePublisherService.isEnabled()) {
            redirectAttributes.addFlashAttribute("errorMessage", "GitHub compliance publisher is disabled or unavailable.");
            return "redirect:/runs/" + runId;
        }

        try {
            validationRunService.reservePublication(runEntity, userEmail, publishRequest);
        } catch (ResponseStatusException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getReason());
            return "redirect:/runs/" + runId;
        } catch (IllegalStateException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
            return "redirect:/runs/" + runId;
        } catch (Exception ex) {
            log.error("Failed to reserve validation publication in database for runId={}", runId, ex);
            redirectAttributes.addFlashAttribute("errorMessage", "Could not reserve publication slot: " + ex.getMessage());
            return "redirect:/runs/" + runId;
        }

        CompliancePublicationResult result;
        try {
            result = gitHubCompliancePublisherService.publish(publishRequest);
        } catch (Exception ex) {
            if (!validationRunService.isReconciliationRequired(runId)) {
                gitHubCompliancePublisherService.releaseClaim(runId);
                safeReleaseReservation(runEntity);
            }
            log.error("Failed to publish compliance report for runId={}", runId, ex);
            String message = sanitizeFlashErrorMessage(ex.getMessage(), "Unknown GitHub publisher error");
            redirectAttributes.addFlashAttribute("errorMessage", "GitHub publishing failed: " + message);
            return "redirect:/runs/" + runId;
        }

        if (result == null || !result.success()) {
            if (!validationRunService.isReconciliationRequired(runId)) {
                gitHubCompliancePublisherService.releaseClaim(runId);
                safeReleaseReservation(runEntity);
            }
            String failureReason = result != null && result.errorMessage() != null
                    ? sanitizeFlashErrorMessage(result.errorMessage(), "GitHub publishing operation did not succeed")
                    : "GitHub publishing operation did not succeed";
            redirectAttributes.addFlashAttribute("errorMessage", "Publication failed: " + failureReason);
            return "redirect:/runs/" + runId;
        }

        try {
            validationRunService.recordPublication(runEntity, userEmail, publishRequest, result);
        } catch (Exception firstEx) {
            log.warn("Initial attempt to persist validation publication failed for runId={}, retrying once: {}",
                    runId, firstEx.getMessage());
            try {
                validationRunService.recordPublication(runEntity, userEmail, publishRequest, result);
            } catch (Exception ex) {
                // Keep reservation and in-memory claim locked so a retry does not open a duplicate PR on GitHub
                validationRunService.markReconciliationRequired(runId);
                log.error("Failed to persist validation publication to database for runId={} after GitHub merge ({})",
                        runId, result.prUrl(), ex);
                String safeReason = sanitizeFlashErrorMessage(ex.getMessage(), "database error");
                redirectAttributes.addFlashAttribute("errorMessage",
                        "Publication merged to GitHub but failed to update local database: " + safeReason
                                + ". The run remains locked for reconciliation.");
                return "redirect:/runs/" + runId;
            }
        }

        redirectAttributes.addFlashAttribute("successMessage",
                "Compliance report successfully published! View live report at " + result.reportUrl());
        redirectAttributes.addFlashAttribute("justPublished", true);

        return "redirect:/runs/" + runId;
    }

    private static String sanitizeFlashErrorMessage(String rawMessage, String fallback) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return fallback;
        }
        // Strip raw JSON response bodies and newlines from exception messages shown in UI flash alerts
        String cleaned = rawMessage.replace('\r', ' ').replace('\n', ' ').trim();
        int jsonStart = cleaned.indexOf('{');
        if (jsonStart > 0) {
            cleaned = cleaned.substring(0, jsonStart).trim();
            if (cleaned.endsWith(":")) {
                cleaned = cleaned.substring(0, cleaned.length() - 1).trim();
            }
        }
        if (cleaned.length() > 200) {
            cleaned = cleaned.substring(0, 197) + "...";
        }
        return cleaned.isEmpty() ? fallback : cleaned;
    }

    private static boolean containsIgnoreCase(String value, String needle) {
        if (value == null || needle == null || needle.isEmpty()) {
            return false;
        }
        return value.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    private void safeReleaseReservation(ValidationRun runEntity) {
        try {
            validationRunService.releasePublicationReservation(runEntity);
        } catch (Exception releaseEx) {
            log.warn("Failed to release publication reservation for runId={}: {}",
                    runEntity != null ? runEntity.getId() : null, releaseEx.getMessage());
        }
    }

    @PostMapping("/runs/{runId}/delete")
    public String deleteRun(@PathVariable UUID runId, Authentication authentication) {
        validationRunService.deleteRun(runId, actorEmail(authentication), isAdmin(authentication));
        return "redirect:/";
    }

    @GetMapping(value = "/runs/{runId}/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Resource> exportRun(@PathVariable UUID runId, Authentication authentication) throws Exception {
        Object run = validationRunService.getRun(runId, actorEmail(authentication), isAdmin(authentication));
        if (run == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        Object tests = validationRunService.getTestResults(runId, actorEmail(authentication), isAdmin(authentication));
        Map<String, Object> exportData = new HashMap<>();
        exportData.put("run", run);
        exportData.put("tests", tests);

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        byte[] json = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(exportData);
        
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"validation-run-" + runId + ".json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ByteArrayResource(json));
    }

    private String actorEmail(Authentication authentication) {
        return AuthenticatedUser.email(authentication);
    }

    private boolean isAdmin(Authentication authentication) {
        return AuthenticatedUser.isAdmin(authentication);
    }

    private String currentUserRole(Authentication authentication) {
        return isAdmin(authentication) ? ROLE_ADMIN : ROLE_USER;
    }

    private String resolveDisplayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        String fallback = AuthenticatedUser.displayName(authentication);
        return mgmtUserService.resolveDisplayName(AuthenticatedUser.email(authentication), fallback);
    }
}
