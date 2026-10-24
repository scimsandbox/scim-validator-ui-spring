package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ComplianceScoreService {

    private static final Logger log = LoggerFactory.getLogger(ComplianceScoreService.class);
    private static final Pattern TEST_ID_PATTERN = Pattern.compile("^([A-Z0-9_]+):\\s*.*");

    public static final List<String> OPTIONAL_CAPABILITIES = List.of(
            "patch", "filter", "sort", "etag", "bulk", "search",
            "changePassword", "enterprise", "cursorPagination", "async"
    );

    private static final Map<String, String> CAPABILITY_TITLES = Map.of(
            "patch", "PATCH Operations (RFC 7644 §3.5.2)",
            "filter", "Filtering (RFC 7644 §3.4.2.2)",
            "sort", "Sorting (RFC 7644 §3.4.2.3)",
            "etag", "ETags & Concurrency (RFC 7644 §3.14)",
            "bulk", "Bulk Operations (RFC 7644 §3.7)",
            "search", ".search Endpoint (RFC 7644 §3.4.3)",
            "changePassword", "Password Change (RFC 7643 §5)",
            "enterprise", "Enterprise User Extension (RFC 7643 §4.3)",
            "cursorPagination", "Cursor Pagination (RFC 9865)",
            "async", "Asynchronous Operations (RFC 9967)"
    );

    private static final Map<String, String> CAPABILITY_SECTIONS = Map.of(
            "patch", "RFC 7644 §3.5.2",
            "filter", "RFC 7644 §3.4.2.2",
            "sort", "RFC 7644 §3.4.2.3",
            "etag", "RFC 7644 §3.14",
            "bulk", "RFC 7644 §3.7",
            "search", "RFC 7644 §3.4.3",
            "changePassword", "RFC 7643 §5",
            "enterprise", "RFC 7643 §4.3",
            "cursorPagination", "RFC 9865",
            "async", "RFC 9967"
    );

    private final SpecCatalogService specCatalogService;
    private final ObjectMapper objectMapper;

    public ComplianceScoreService(SpecCatalogService specCatalogService) {
        this(specCatalogService, new ObjectMapper());
    }

    @Autowired
    public ComplianceScoreService(SpecCatalogService specCatalogService, @Autowired(required = false) ObjectMapper objectMapper) {
        this.specCatalogService = specCatalogService;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    /**
     * Convenience overload using test results from run.
     */
    public ComplianceScorecardView computeScorecard(ValidationRun run) {
        List<ValidationTestResult> results = run != null && run.getTestResults() != null
                ? run.getTestResults() : Collections.emptyList();
        return computeScorecard(run, results, Collections.emptyList());
    }

    /**
     * Compute full ComplianceScorecardView for a given ValidationRun.
     */
    public ComplianceScorecardView computeScorecard(
            ValidationRun run,
            List<ValidationTestResult> testResults,
            List<ValidationHttpExchange> exchanges) {

        List<ValidationTestResult> safeResults = testResults != null ? testResults : Collections.emptyList();
        List<ValidationHttpExchange> safeExchanges = exchanges != null ? exchanges : Collections.emptyList();

        Map<String, SpecRequirement> catalog = specCatalogService.getRequirements();

        // 1. Index test results by test ID
        Map<String, ValidationTestResult> resultsByTestId = new LinkedHashMap<>();
        for (ValidationTestResult tr : safeResults) {
            String testId = extractTestId(tr);
            if (testId != null) {
                resultsByTestId.put(testId, tr);
            }
        }

        // 2. Discover changePassword capability from exchanges
        Boolean changePasswordSupported = discoverChangePassword(safeExchanges);

        // 3. Evaluate the 10 Optional Capabilities
        Map<String, CapabilityStatus> capabilityStatusMap = evaluateCapabilities(
                resultsByTestId, changePasswordSupported);

        // Set of capabilities that were EXECUTED (at least 1 test SUCCESS or FAILED, not ABORTED)
        Set<String> activeCapabilities = new HashSet<>();
        for (Map.Entry<String, CapabilityStatus> entry : capabilityStatusMap.entrySet()) {
            if (entry.getValue().executedTests() > 0) {
                activeCapabilities.add(entry.getKey());
            }
        }

        // 4. Trace Requirements & Determine Active Scope
        List<RequirementTraceResult> traceResults = new ArrayList<>();
        double totalEarned = 0.0;
        double totalWeight = 0.0;

        // Normative accumulators
        double mustEarned = 0.0, mustTotal = 0.0;
        int mustActive = 0, mustCompliant = 0, mustPartial = 0, mustFailed = 0;

        double shouldEarned = 0.0, shouldTotal = 0.0;
        int shouldActive = 0, shouldCompliant = 0, shouldPartial = 0, shouldFailed = 0;

        double mayEarned = 0.0, mayTotal = 0.0;
        int mayActive = 0, mayCompliant = 0, mayPartial = 0, mayFailed = 0;

        int activeCount = 0;
        int excludedCount = 0;
        int untestedCount = 0;

        for (SpecRequirement req : catalog.values()) {
            String cap = req.capability() != null ? req.capability().trim() : "none";
            boolean isCore = "none".equalsIgnoreCase(cap) || cap.isEmpty();
            boolean capActive = isCore || activeCapabilities.contains(cap);

            // Find all tests mapping to this requirement
            List<String> mappedTestIds = specCatalogService.getTestsForRequirement(req.id());
            int totalTestsForReq = mappedTestIds.size();
            int executedTestsForReq = 0;
            int passedTestsForReq = 0;
            int failedTestsForReq = 0;
            int abortedTestsForReq = 0;

            for (String tid : mappedTestIds) {
                ValidationTestResult tr = resultsByTestId.get(tid);
                if (tr != null) {
                    String status = tr.getStatus() != null ? tr.getStatus().toUpperCase() : "UNKNOWN";
                    switch (status) {
                        case "SUCCESS" -> {
                            passedTestsForReq++;
                            executedTestsForReq++;
                        }
                        case "FAILED" -> {
                            failedTestsForReq++;
                            executedTestsForReq++;
                        }
                        case "ABORTED" -> abortedTestsForReq++;
                    }
                }
            }

            boolean inActiveScope = false;
            double earned = 0.0;
            int w = req.getWeight();
            String status;

            if (!capActive) {
                status = "EXCLUDED_CAPABILITY";
                excludedCount++;
            } else if (executedTestsForReq == 0) {
                status = "UNTESTED";
                untestedCount++;
            } else {
                inActiveScope = true;
                activeCount++;
                earned = w * ((double) passedTestsForReq / executedTestsForReq);
                totalEarned += earned;
                totalWeight += w;

                if (passedTestsForReq == executedTestsForReq) {
                    status = "COMPLIANT";
                } else if (passedTestsForReq > 0) {
                    status = "PARTIAL";
                } else {
                    status = "FAILED";
                }

                // Tally normative metrics
                String level = req.level() != null ? req.level().toUpperCase() : "MAY";
                switch (level) {
                    case "MUST" -> {
                        mustActive++;
                        mustTotal += w;
                        mustEarned += earned;
                        if (passedTestsForReq == executedTestsForReq) mustCompliant++;
                        else if (passedTestsForReq > 0) mustPartial++;
                        else mustFailed++;
                    }
                    case "SHOULD" -> {
                        shouldActive++;
                        shouldTotal += w;
                        shouldEarned += earned;
                        if (passedTestsForReq == executedTestsForReq) shouldCompliant++;
                        else if (passedTestsForReq > 0) shouldPartial++;
                        else shouldFailed++;
                    }
                    case "MAY", "OPTIONAL" -> {
                        mayActive++;
                        mayTotal += w;
                        mayEarned += earned;
                        if (passedTestsForReq == executedTestsForReq) mayCompliant++;
                        else if (passedTestsForReq > 0) mayPartial++;
                        else mayFailed++;
                    }
                }
            }

            traceResults.add(new RequirementTraceResult(
                    req.id(), req.rfc(), req.section(), req.title(), req.level(),
                    w, req.capability(), inActiveScope, totalTestsForReq, executedTestsForReq,
                    passedTestsForReq, failedTestsForReq, abortedTestsForReq, earned, status, mappedTestIds
            ));
        }

        // 5. Final Score & Rounding
        int coreScore = totalWeight > 0 ? (int) Math.round((100.0 * totalEarned) / totalWeight) : 0;
        ColourGradient gradient = ColourGradient.forScore(coreScore);

        // 6. Normative Breakdown
        NormativeBreakdown mustBreakdown = NormativeBreakdown.of(
                "MUST", 3, mustActive, mustCompliant, mustPartial, mustFailed, mustEarned, mustTotal);
        NormativeBreakdown shouldBreakdown = NormativeBreakdown.of(
                "SHOULD", 2, shouldActive, shouldCompliant, shouldPartial, shouldFailed, shouldEarned, shouldTotal);
        NormativeBreakdown mayBreakdown = NormativeBreakdown.of(
                "MAY", 1, mayActive, mayCompliant, mayPartial, mayFailed, mayEarned, mayTotal);

        // 7. Capability Summary Counts
        List<CapabilityStatus> capabilitiesList = new ArrayList<>(capabilityStatusMap.values());
        int supportedCaps = 0;
        int compliantCaps = 0;
        for (CapabilityStatus cs : capabilitiesList) {
            if (cs.isSupported()) supportedCaps++;
            if (cs.status() == CapabilitySupportLevel.SUPPORTED_COMPLIANT) compliantCaps++;
        }

        // 8. Publish Eligibility Evaluation
        String runStatus = run != null && run.getStatus() != null ? run.getStatus().toUpperCase() : "UNKNOWN";
        boolean isTerminal = "PASSED".equals(runStatus) || "FAILED".equals(runStatus);
        boolean meetsThreshold = coreScore >= 50;
        boolean publishEligible = isTerminal && meetsThreshold;
        String ineligibilityReason = null;
        if (!isTerminal) {
            if ("RUNNING".equals(runStatus)) {
                ineligibilityReason = "Validation run is still running.";
            } else if ("ERROR".equals(runStatus)) {
                ineligibilityReason = "Validation run encountered an execution error.";
            } else {
                ineligibilityReason = "Validation run status (" + runStatus + ") is not eligible for publication.";
            }
        } else if (!meetsThreshold) {
            ineligibilityReason = "Core RFC Conformance score (" + coreScore + "%) is below the minimum 50% publishing threshold.";
        }

        // 9. Per-RFC Summaries
        Map<String, RfcSectionSummary> rfcSummaries = computeRfcSummaries(traceResults);

        return new ComplianceScorecardView(
                run != null ? run.getId() : null,
                run != null ? run.getName() : "Validation Run",
                run != null ? run.getTargetUrl() : "",
                run != null ? run.getExecutedAt() : OffsetDateTime.now(),
                runStatus,
                coreScore,
                gradient,
                publishEligible,
                ineligibilityReason,
                mustBreakdown,
                shouldBreakdown,
                mayBreakdown,
                capabilitiesList,
                supportedCaps,
                compliantCaps,
                OPTIONAL_CAPABILITIES.size(),
                catalog.size(),
                activeCount,
                excludedCount,
                untestedCount,
                rfcSummaries,
                traceResults
        );
    }

    public boolean isEligibleForPublish(ComplianceScorecardView scorecard, ValidationRun run) {
        if (scorecard == null || run == null) return false;
        String status = run.getStatus() != null ? run.getStatus().toUpperCase() : "";
        boolean isTerminal = "PASSED".equals(status) || "FAILED".equals(status);
        return isTerminal && scorecard.coreScore() >= 50;
    }

    private Map<String, CapabilityStatus> evaluateCapabilities(
            Map<String, ValidationTestResult> resultsByTestId,
            Boolean changePasswordSupported) {

        Map<String, CapabilityStatus> result = new LinkedHashMap<>();

        for (String cap : OPTIONAL_CAPABILITIES) {
            if ("changePassword".equals(cap)) {
                boolean supported = Boolean.TRUE.equals(changePasswordSupported);
                CapabilitySupportLevel lvl = supported
                        ? CapabilitySupportLevel.SUPPORTED_COMPLIANT
                        : CapabilitySupportLevel.UNSUPPORTED;
                result.put(cap, CapabilityStatus.of(
                        cap,
                        CAPABILITY_TITLES.get(cap),
                        CAPABILITY_SECTIONS.get(cap),
                        lvl,
                        1,
                        supported ? 1 : 0,
                        supported ? 1 : 0,
                        0,
                        supported ? 0 : 1
                ));
                continue;
            }

            List<String> capTestIds = specCatalogService.getTestsForCapability(cap);
            int total = capTestIds.size();
            int passed = 0;
            int failed = 0;
            int aborted = 0;

            for (String tid : capTestIds) {
                ValidationTestResult tr = resultsByTestId.get(tid);
                if (tr != null) {
                    String status = tr.getStatus() != null ? tr.getStatus().toUpperCase() : "UNKNOWN";
                    switch (status) {
                        case "SUCCESS" -> passed++;
                        case "FAILED" -> failed++;
                        case "ABORTED" -> aborted++;
                    }
                }
            }

            int executed = passed + failed;
            CapabilitySupportLevel lvl;
            if (executed == 0) {
                lvl = CapabilitySupportLevel.UNSUPPORTED;
            } else if (failed == 0) {
                lvl = CapabilitySupportLevel.SUPPORTED_COMPLIANT;
            } else {
                lvl = CapabilitySupportLevel.SUPPORTED_PARTIAL;
            }

            result.put(cap, CapabilityStatus.of(
                    cap,
                    CAPABILITY_TITLES.get(cap),
                    CAPABILITY_SECTIONS.get(cap),
                    lvl,
                    total,
                    executed,
                    passed,
                    failed,
                    aborted
            ));
        }

        return result;
    }

    private Boolean discoverChangePassword(List<ValidationHttpExchange> exchanges) {
        if (exchanges == null) return false;
        for (ValidationHttpExchange ex : exchanges) {
            String url = ex.getUrl();
            if (url != null && url.contains("/ServiceProviderConfig") &&
                    ex.getResponseStatus() != null && ex.getResponseStatus() == 200 &&
                    ex.getResponseBody() != null && !ex.getResponseBody().isBlank()) {
                try {
                    JsonNode root = objectMapper.readTree(ex.getResponseBody());
                    JsonNode cpNode = root.get("changePassword");
                    if (cpNode != null && cpNode.has("supported")) {
                        return cpNode.get("supported").asBoolean();
                    }
                } catch (Exception e) {
                    log.warn("Failed to parse ServiceProviderConfig response body: {}", e.getMessage());
                }
            }
        }
        return false;
    }

    private Map<String, RfcSectionSummary> computeRfcSummaries(List<RequirementTraceResult> traceResults) {
        Map<String, List<RequirementTraceResult>> byRfc = new LinkedHashMap<>();
        for (RequirementTraceResult r : traceResults) {
            byRfc.computeIfAbsent(r.rfc(), k -> new ArrayList<>()).add(r);
        }

        Map<String, String> titles = Map.of(
                "7643", "RFC 7643: Core Schemas",
                "7644", "RFC 7644: Protocol",
                "9865", "RFC 9865: Cursor Pagination",
                "9967", "RFC 9967: Asynchronous Operations"
        );

        Map<String, RfcSectionSummary> summaries = new LinkedHashMap<>();
        for (String rfc : List.of("7643", "7644", "9865", "9967")) {
            List<RequirementTraceResult> list = byRfc.getOrDefault(rfc, Collections.emptyList());
            int total = list.size();
            int active = 0;
            int compliant = 0;
            double earned = 0.0;
            double totalPts = 0.0;

            for (RequirementTraceResult r : list) {
                if (r.inActiveScope()) {
                    active++;
                    earned += r.earnedWeight();
                    totalPts += r.weight();
                    if ("COMPLIANT".equals(r.status())) compliant++;
                }
            }

            int percent = totalPts > 0 ? (int) Math.round((100.0 * earned) / totalPts) : 100;
            summaries.put(rfc, new RfcSectionSummary(
                    rfc, titles.getOrDefault(rfc, "RFC " + rfc), total, active, compliant, earned, totalPts, percent));
        }

        return summaries;
    }

    public static String extractTestId(ValidationTestResult tr) {
        if (tr == null) return null;
        String id = extractTestId(tr.getDisplayName());
        if (id != null) return id;
        id = extractTestId(tr.getTestName());
        if (id != null) return id;
        id = extractTestId(tr.getTestIdentifier());
        return id;
    }

    public static String extractTestId(String text) {
        if (text == null) return null;
        String trimmed = text.trim();
        Matcher m = TEST_ID_PATTERN.matcher(trimmed);
        if (m.find()) {
            return m.group(1);
        }
        if (trimmed.matches("^[A-Z0-9_]+$")) {
            return trimmed;
        }
        return null;
    }
}
