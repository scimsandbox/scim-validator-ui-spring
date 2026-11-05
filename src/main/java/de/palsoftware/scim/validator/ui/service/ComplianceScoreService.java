package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ComplianceScoreService {

    private static final Logger log = LoggerFactory.getLogger(ComplianceScoreService.class);
    public static final Pattern TEST_ID_PATTERN = SpecCatalogService.TEST_ID_PATTERN;
    public static final int DEFAULT_MIN_PUBLISH_SCORE = 50;
    public static final int DEFAULT_MIN_CORE_COVERAGE_PERCENT = 50;

    @Value("${app.compliance.min-publish-score:50}")
    private int minPublishScore = DEFAULT_MIN_PUBLISH_SCORE;

    @Value("${app.compliance.min-core-coverage-percent:50}")
    private int minCoreCoveragePercent = DEFAULT_MIN_CORE_COVERAGE_PERCENT;

    public int getMinPublishScore() {
        return minPublishScore;
    }

    public int getMinCoreCoveragePercent() {
        return minCoreCoveragePercent;
    }

    public void setMinCoreCoveragePercent(int minCoreCoveragePercent) {
        this.minCoreCoveragePercent = minCoreCoveragePercent;
    }

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
     *
     * <p>For active requirements mapped to multiple tests across capabilities, tests whose required
     * capability is inactive are excluded from {@code totalTestsForReq} ({@code effectiveTestIds}) so that
     * a core or active requirement is not penalized when an optional capability is unsupported by the server.
     * If all mapped tests for a requirement require inactive capabilities, the requirement itself is classified
     * as {@code EXCLUDED_CAPABILITY} and omitted from the active-scope denominator.</p>
     */
    public ComplianceScorecardView computeScorecard(
            ValidationRun run,
            List<ValidationTestResult> testResults,
            List<ValidationHttpExchange> exchanges) {

        List<ValidationTestResult> safeResults = testResults != null ? testResults : Collections.emptyList();

        Map<String, SpecRequirement> catalog = specCatalogService.getRequirements();

        // 1. Index test results by test ID
        Map<String, ValidationTestResult> resultsByTestId = new LinkedHashMap<>();
        for (ValidationTestResult tr : safeResults) {
            String testId = extractTestId(tr);
            if (testId != null) {
                ValidationTestResult previous = resultsByTestId.put(testId, tr);
                if (previous != null) {
                    log.debug("Duplicate test result encountered for testId={} in runId={}, overwriting previous status {}",
                            testId, run != null ? run.getId() : null, previous.getStatus());
                }
            }
        }

        // 2. Evaluate the 10 Optional Capabilities
        Map<String, CapabilityStatus> capabilityStatusMap = evaluateCapabilities(resultsByTestId);

        // Set of capabilities that were EXECUTED (at least 1 test SUCCESS or FAILED, not ABORTED)
        Set<String> activeCapabilities = new HashSet<>();
        for (Map.Entry<String, CapabilityStatus> entry : capabilityStatusMap.entrySet()) {
            if (entry.getValue().executedTests() > 0) {
                activeCapabilities.add(entry.getKey());
            }
        }

        // 3. Determine once whether any mapped test in the catalog was executed (SUCCESS or FAILED)
        boolean hasAnyExecuted = resultsByTestId.entrySet().stream()
                .filter(e -> isMappedTestId(e.getKey(), catalog.keySet()))
                .map(Map.Entry::getValue)
                .anyMatch(tr -> tr != null && ("SUCCESS".equalsIgnoreCase(tr.getStatus()) || "FAILED".equalsIgnoreCase(tr.getStatus())));

        boolean hasAnyCoreExecuted = catalog.values().stream()
                .filter(SpecRequirement::isCore)
                .flatMap(req -> {
                    List<String> reqTests = specCatalogService.getTestsForRequirement(req.id());
                    return reqTests != null ? reqTests.stream() : java.util.stream.Stream.empty();
                })
                .map(resultsByTestId::get)
                .anyMatch(tr -> tr != null && ("SUCCESS".equalsIgnoreCase(tr.getStatus()) || "FAILED".equalsIgnoreCase(tr.getStatus())));

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
        int testableCoreReqs = 0;
        int executedCoreReqs = 0;

        for (SpecRequirement req : catalog.values()) {
            String cap = req.capability() != null ? req.capability().trim() : SpecRequirement.CORE_CAPABILITY;
            boolean isCore = SpecRequirement.CORE_CAPABILITY.equalsIgnoreCase(cap) || cap.isEmpty();
            boolean capActive = isCore || activeCapabilities.contains(cap);

            // Find all tests mapping to this requirement
            List<String> mappedTestIds = specCatalogService.getTestsForRequirement(req.id());

            // Multi-capability test filtering: for active requirements mapped to multiple tests across
            // capabilities, exclude tests whose required capability is inactive from totalTestsForReq
            // so a core requirement is not penalized when an optional capability is unsupported.
            // If all mapped tests require an inactive capability, the requirement becomes EXCLUDED_CAPABILITY.
            List<String> eligibleTestIds = mappedTestIds.stream().filter(tid -> {
                List<String> testCaps = specCatalogService.getTestMapping(tid)
                        .map(TestSpecMapping::requiredCapabilities)
                        .orElse(Collections.emptyList());
                return testCaps.stream().allMatch(c -> SpecRequirement.CORE_CAPABILITY.equalsIgnoreCase(c) || activeCapabilities.contains(c));
            }).toList();

            if (capActive && eligibleTestIds.isEmpty() && !mappedTestIds.isEmpty()) {
                capActive = false;
            }

            List<String> effectiveTestIds = capActive ? eligibleTestIds : mappedTestIds;
            int totalTestsForReq = effectiveTestIds.size();
            int executedTestsForReq = 0;
            int passedTestsForReq = 0;
            int failedTestsForReq = 0;
            int abortedTestsForReq = 0;

            for (String tid : effectiveTestIds) {
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
                        case "ABORTED", "SKIPPED" -> abortedTestsForReq++;
                    }
                }
            }

            boolean isNaDisposition = "na".equalsIgnoreCase(req.disposition());
            boolean isOptionalDisposition = "optional".equalsIgnoreCase(req.disposition());
            boolean isOptionalReq = isOptionalDisposition || req.isMayOrOptional();
            boolean capExecuted = isCore ? hasAnyCoreExecuted : activeCapabilities.contains(cap);
            boolean isAbortedMaySubfeature = capExecuted && executedTestsForReq == 0 && abortedTestsForReq > 0 && req.isMayOrOptional();

            boolean inActiveScope = false;
            double earned = 0.0;
            int w = req.getWeight();
            String status;

            if (!capActive || (isNaDisposition && executedTestsForReq == 0) || isAbortedMaySubfeature) {
                status = "EXCLUDED_CAPABILITY";
                excludedCount++;
            } else if (!hasAnyExecuted) {
                status = "UNTESTED";
                untestedCount++;
            } else {
                inActiveScope = true;
                totalWeight += w;

                if (totalTestsForReq > 0) {
                    earned = w * ((double) passedTestsForReq / totalTestsForReq);
                }
                totalEarned += earned;

                if (executedTestsForReq == 0) {
                    status = "UNTESTED";
                    untestedCount++;
                } else {
                    activeCount++;
                    if (passedTestsForReq == totalTestsForReq && abortedTestsForReq == 0 && totalTestsForReq > 0) {
                        status = "COMPLIANT";
                    } else if (passedTestsForReq > 0) {
                        status = "PARTIAL";
                    } else {
                        status = "FAILED";
                    }
                }

                // Tally normative metrics
                String level = req.level() != null ? req.level().toUpperCase() : "MAY";
                switch (level) {
                    case "MUST" -> {
                        mustTotal += w;
                        mustEarned += earned;
                        if ("COMPLIANT".equals(status)) {
                            mustActive++;
                            mustCompliant++;
                        } else if ("PARTIAL".equals(status)) {
                            mustActive++;
                            mustPartial++;
                        } else if ("FAILED".equals(status)) {
                            mustActive++;
                            mustFailed++;
                        }
                    }
                    case "SHOULD" -> {
                        shouldTotal += w;
                        shouldEarned += earned;
                        if ("COMPLIANT".equals(status)) {
                            shouldActive++;
                            shouldCompliant++;
                        } else if ("PARTIAL".equals(status)) {
                            shouldActive++;
                            shouldPartial++;
                        } else if ("FAILED".equals(status)) {
                            shouldActive++;
                            shouldFailed++;
                        }
                    }
                    case "MAY", "OPTIONAL" -> {
                        mayTotal += w;
                        mayEarned += earned;
                        if ("COMPLIANT".equals(status)) {
                            mayActive++;
                            mayCompliant++;
                        } else if ("PARTIAL".equals(status)) {
                            mayActive++;
                            mayPartial++;
                        } else if ("FAILED".equals(status)) {
                            mayActive++;
                            mayFailed++;
                        }
                    }
                }
            }

            // Core Execution Coverage Protection (TASK-59):
            // Do not penalize core execution coverage for optional sub-features that abort.
            boolean isAbortedOptional = executedTestsForReq == 0 && abortedTestsForReq > 0 && isOptionalReq;
            if (capActive && isCore && !isNaDisposition && !isAbortedOptional && totalTestsForReq > 0 && !"EXCLUDED_CAPABILITY".equals(status)) {
                testableCoreReqs++;
                if (executedTestsForReq > 0) {
                    executedCoreReqs++;
                }
            }

            traceResults.add(new RequirementTraceResult(
                    req.id(), req.rfc(), req.section(), req.title(), req.level(),
                    w, req.capability(), inActiveScope, totalTestsForReq, executedTestsForReq,
                    passedTestsForReq, failedTestsForReq, abortedTestsForReq, earned, status, mappedTestIds
            ));
        }

        // 5. Final Score & Rounding (TASK-62: 99% cap on active failures)
        int coreScore = totalWeight > 0 ? (int) Math.round((100.0 * totalEarned) / totalWeight) : 0;
        if (totalEarned < totalWeight && coreScore == 100) {
            coreScore = 99;
        }
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
        String runStatus = run != null && run.getStatus() != null ? run.getStatus().toUpperCase(Locale.ROOT) : "UNKNOWN";
        boolean isTerminal = "PASSED".equals(runStatus) || "FAILED".equals(runStatus) || "PARTIAL".equals(runStatus);
        boolean meetsThreshold = coreScore >= minPublishScore;
        int coreCoveragePercent = testableCoreReqs > 0
                ? (int) Math.round((100.0 * executedCoreReqs) / testableCoreReqs)
                : (activeCount > 0 ? 100 : 0);
        if (executedCoreReqs < testableCoreReqs && coreCoveragePercent == 100) {
            coreCoveragePercent = 99;
        }
        boolean meetsCoverage = activeCount > 0 && coreCoveragePercent >= minCoreCoveragePercent;
        boolean publishEligible = isTerminal && meetsThreshold && meetsCoverage;
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
            ineligibilityReason = "Core RFC Conformance score (" + coreScore + "%) is below the minimum " + minPublishScore + "% publishing threshold.";
        } else if (!meetsCoverage) {
            ineligibilityReason = "Core requirement execution coverage (" + coreCoveragePercent + "%) is below the minimum "
                    + minCoreCoveragePercent + "% publishing threshold (" + executedCoreReqs + "/" + testableCoreReqs + " testable core requirements executed).";
        }

        // 9. Per-RFC Summaries & Core-Only Conformance (TASK-63) & Conformance Tier (Policy 3.3)
        Map<String, RfcSectionSummary> rfcSummaries = computeRfcSummaries(traceResults);
        double coreOnlyEarnedPoints = computeCoreOnlyEarnedPoints(traceResults);
        double coreOnlyTotalPoints = computeCoreOnlyTotalPoints(traceResults);
        int coreOnlyScore = computeCoreOnlyScore(traceResults);
        String conformanceTierLabel = ComplianceScorecardView.computeConformanceTierLabel(
                coreScore, coreCoveragePercent, mustBreakdown);

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
                traceResults,
                coreOnlyScore,
                coreOnlyEarnedPoints,
                coreOnlyTotalPoints,
                coreCoveragePercent,
                conformanceTierLabel
        );
    }

    private boolean isMappedTestId(String testId, Collection<String> requirementIds) {
        if (testId == null) return false;
        if (specCatalogService.getTestMapping(testId).isPresent()) {
            return true;
        }
        for (String reqId : requirementIds) {
            List<String> reqTests = specCatalogService.getTestsForRequirement(reqId);
            if (reqTests != null && reqTests.contains(testId)) {
                return true;
            }
        }
        return false;
    }

    public boolean isEligibleForPublish(ComplianceScorecardView scorecard, ValidationRun run) {
        if (scorecard == null || run == null) return false;
        String status = run.getStatus() != null ? run.getStatus().toUpperCase(Locale.ROOT) : "";
        boolean isTerminal = "PASSED".equals(status) || "FAILED".equals(status) || "PARTIAL".equals(status);
        return isTerminal && scorecard.coreScore() >= minPublishScore && meetsMinimumCoverage(scorecard);
    }

    private boolean meetsMinimumCoverage(ComplianceScorecardView scorecard) {
        List<RequirementTraceResult> matrix = scorecard.requirementMatrix();
        if (matrix != null && !matrix.isEmpty()) {
            int testableCore = 0;
            int executedCore = 0;
            for (RequirementTraceResult r : matrix) {
                String cap = r.capability() != null ? r.capability().trim() : SpecRequirement.CORE_CAPABILITY;
                boolean isCore = SpecRequirement.CORE_CAPABILITY.equalsIgnoreCase(cap) || cap.isEmpty();
                boolean isNaDisposition = specCatalogService.getRequirement(r.id())
                        .map(spec -> "na".equalsIgnoreCase(spec.disposition()))
                        .orElse(false);
                boolean isOptionalDisposition = specCatalogService.getRequirement(r.id())
                        .map(spec -> "optional".equalsIgnoreCase(spec.disposition()) || spec.isMayOrOptional())
                        .orElse(false);
                boolean isAbortedOptional = r.executedTests() == 0 && r.abortedTests() > 0 && isOptionalDisposition;
                if (isCore && !isNaDisposition && !isAbortedOptional && r.totalTests() > 0 && !"EXCLUDED_CAPABILITY".equals(r.status())) {
                    testableCore++;
                    if (r.executedTests() > 0) {
                        executedCore++;
                    }
                }
            }
            int coveragePercent = testableCore > 0
                    ? (int) Math.round((100.0 * executedCore) / testableCore)
                    : (scorecard.activeRequirementsCount() > 0 ? 100 : 0);
            if (executedCore < testableCore && coveragePercent == 100) {
                coveragePercent = 99;
            }
            return scorecard.activeRequirementsCount() > 0 && coveragePercent >= minCoreCoveragePercent;
        }
        return scorecard.activeRequirementsCount() > 0 || scorecard.catalogRequirementsTotal() == 0;
    }

    private Map<String, CapabilityStatus> evaluateCapabilities(
            Map<String, ValidationTestResult> resultsByTestId) {

        Map<String, CapabilityStatus> result = new LinkedHashMap<>();

        for (String cap : OPTIONAL_CAPABILITIES) {
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
                        case "ABORTED", "SKIPPED" -> aborted++;
                    }
                }
            }

            int executed = passed + failed;
            CapabilitySupportLevel lvl;
            if (executed == 0) {
                lvl = CapabilitySupportLevel.UNSUPPORTED;
            } else if (failed == 0 && aborted == 0 && passed == total) {
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

            int percent = totalPts > 0 ? (int) Math.round((100.0 * earned) / totalPts) : 0;
            if (earned < totalPts && percent == 100) {
                percent = 99;
            }
            summaries.put(rfc, new RfcSectionSummary(
                    rfc, titles.getOrDefault(rfc, "RFC " + rfc), total, active, compliant, earned, totalPts, percent));
        }

        return summaries;
    }

    public static boolean isCoreOnlyRequirement(SpecRequirement req) {
        return req != null && req.isCore() && req.isScored();
    }

    private boolean isCoreOnlyTrace(RequirementTraceResult r) {
        if (r == null || !r.inActiveScope()) {
            return false;
        }
        Map<String, SpecRequirement> reqs = specCatalogService.getRequirements();
        SpecRequirement req = (reqs != null) ? reqs.get(r.id()) : null;
        if (req == null) {
            req = specCatalogService.getRequirement(r.id()).orElse(null);
        }
        if (req != null) {
            return isCoreOnlyRequirement(req);
        }
        String cap = r.capability() != null ? r.capability().trim() : SpecRequirement.CORE_CAPABILITY;
        return SpecRequirement.CORE_CAPABILITY.equalsIgnoreCase(cap) || cap.isEmpty();
    }

    /**
     * Compute true Core-Only Conformance score (0-100) evaluating only core-tested requirements
     * (capability: "core" and a scored disposition, i.e. everything except optional/na).
     */
    public int computeCoreOnlyScore(ComplianceScorecardView scorecard) {
        if (scorecard == null) {
            return 0;
        }
        if (scorecard.requirementMatrix() == null || scorecard.requirementMatrix().isEmpty()) {
            return scorecard.coreOnlyScore();
        }
        return computeCoreOnlyScore(scorecard.requirementMatrix());
    }

    public int computeCoreOnlyScore(List<RequirementTraceResult> traceResults) {
        if (traceResults == null || traceResults.isEmpty()) {
            return 0;
        }
        double earned = computeCoreOnlyEarnedPoints(traceResults);
        double weight = computeCoreOnlyTotalPoints(traceResults);
        if (weight <= 0) return 0;
        int score = (int) Math.round((100.0 * earned) / weight);
        if (earned < weight && score == 100) {
            score = 99;
        }
        return score;
    }

    /**
     * Compute composite Active-Scope Conformance score (0-100) across all active requirements.
     * Denominator is the total weight of all requirements in active scope.
     */
    public int computeActiveScopeScore(ComplianceScorecardView scorecard) {
        if (scorecard == null) return 0;
        return scorecard.coreScore();
    }

    public double computeCoreOnlyEarnedPoints(ComplianceScorecardView scorecard) {
        if (scorecard == null) return 0.0;
        if (scorecard.requirementMatrix() == null || scorecard.requirementMatrix().isEmpty()) {
            return scorecard.coreOnlyEarnedPoints();
        }
        return computeCoreOnlyEarnedPoints(scorecard.requirementMatrix());
    }

    public double computeCoreOnlyEarnedPoints(List<RequirementTraceResult> traceResults) {
        if (traceResults == null) return 0.0;
        return traceResults.stream()
                .filter(this::isCoreOnlyTrace)
                .mapToDouble(RequirementTraceResult::earnedWeight)
                .sum();
    }

    public double computeCoreOnlyTotalPoints(ComplianceScorecardView scorecard) {
        if (scorecard == null) return 0.0;
        if (scorecard.requirementMatrix() == null || scorecard.requirementMatrix().isEmpty()) {
            return scorecard.coreOnlyTotalPoints();
        }
        return computeCoreOnlyTotalPoints(scorecard.requirementMatrix());
    }

    public double computeCoreOnlyTotalPoints(List<RequirementTraceResult> traceResults) {
        if (traceResults == null) return 0.0;
        return traceResults.stream()
                .filter(this::isCoreOnlyTrace)
                .mapToDouble(RequirementTraceResult::weight)
                .sum();
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
        if (SpecCatalogService.RAW_TEST_ID_SYNTAX.matcher(trimmed).matches()) {
            return trimmed;
        }
        return null;
    }
}
