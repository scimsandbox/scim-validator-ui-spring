package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.time.OffsetDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ComplianceScoreServiceTest {

    private static SpecCatalogService catalogService;
    private static ComplianceScoreService scoreService;

    @BeforeAll
    static void setUp() {
        catalogService = CoveredSpecCatalog.create();
        scoreService = new ComplianceScoreService(catalogService, new ObjectMapper());
    }

    /** Score as the service rounds it: never 100 while points are missing. */
    private static int cappedScore(double earned, double total) {
        int score = (int) Math.round((100.0 * earned) / total);
        return (earned < total && score == 100) ? 99 : score;
    }

    private static double coreWeight() {
        return catalogService.getRequirements().values().stream()
                .filter(ComplianceScoreService::isCoreOnlyRequirement)
                .mapToDouble(SpecRequirement::getWeight).sum();
    }

    private ValidationRun createSampleRun(String status) {
        ValidationRun run = new ValidationRun();
        run.setName("Integration SCIM 2.0 Test Run");
        run.setTargetUrl("https://scim.example.com/v2");
        run.setStatus(status);
        run.setExecutedAt(OffsetDateTime.now());
        return run;
    }

    private ValidationTestResult createTestResult(String testId, String displayName, String status) {
        ValidationTestResult tr = new ValidationTestResult();
        tr.setTestIdentifier(testId);
        tr.setDisplayName(displayName);
        tr.setTestName(displayName);
        tr.setStatus(status);
        return tr;
    }

    private ValidationHttpExchange createExchange(String url, int status, String body) {
        ValidationHttpExchange ex = new ValidationHttpExchange();
        ex.setUrl(url);
        ex.setResponseStatus(status);
        ex.setResponseBody(body);
        return ex;
    }

    @Test
    @DisplayName("Perfect 100% run assigns EMERALD gradient, 10/10 capabilities, and publish eligible")
    void testPerfect100Run_EmeraldGradient_AllCapabilitiesSupported() {
        ValidationRun run = createSampleRun("PASSED");

        List<ValidationTestResult> testResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
        }

        ValidationHttpExchange exchange = createExchange(
                "https://scim.example.com/v2/ServiceProviderConfig",
                200,
                "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig\"],\"changePassword\":{\"supported\":true}}"
        );

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(exchange));

        assertThat(scorecard.coreScore()).isEqualTo(100);
        assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.EMERALD);
        assertThat(scorecard.colourGradient().getStartColor()).isEqualTo("#10b981");
        assertThat(scorecard.colourGradient().getEndColor()).isEqualTo("#059669");
        assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(10);
        assertThat(scorecard.compliantCapabilitiesCount()).isEqualTo(10);
        assertThat(scorecard.totalCapabilitiesCount()).isEqualTo(10);
        assertThat(scorecard.publishEligible()).isTrue();
        assertThat(scorecard.publishIneligibilityReason()).isNull();

        assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(scorecard.shouldBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(scorecard.mayBreakdown().conformancePercent()).isEqualTo(100);

        int coveredRequirements = catalogService.getTotalRequirementsCount();
        assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(coveredRequirements);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(coveredRequirements);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(0);
        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(0);

        assertThat(scorecard.getScoreBadgeText()).isEqualTo("100%");
        assertThat(scorecard.getCapabilityBadgeText()).isEqualTo("10/10 caps");
        assertThat(scorecard.coreOnlyScore()).isEqualTo(100);
        assertThat(scorecard.coreOnlyEarnedPoints()).isEqualTo(coreWeight());
        assertThat(scorecard.coreOnlyTotalPoints()).isEqualTo(coreWeight());
        assertThat(scorecard.coreCoveragePercent()).isEqualTo(100);
        assertThat(scorecard.conformanceTierLabel()).isEqualTo("Certified RFC Compliant");
        assertThat(scoreService.computeCoreOnlyScore(scorecard)).isEqualTo(100);
        assertThat(scoreService.computeCoreOnlyEarnedPoints(scorecard)).isEqualTo(coreWeight());
        assertThat(scoreService.computeCoreOnlyTotalPoints(scorecard)).isEqualTo(coreWeight());
        assertThat(scoreService.computeActiveScopeScore(scorecard)).isEqualTo(100);

        for (RequirementTraceResult trace : scorecard.requirementMatrix()) {
            assertThat(trace.rfcUrl())
                    .isEqualTo("https://www.rfc-editor.org/rfc/rfc" + trace.rfc() + "#section-" + trace.section());
            assertThat(trace.rfcLabel())
                    .isEqualTo("RFC " + trace.rfc() + " §" + trace.section());
        }
    }

    @Test
    @DisplayName("Minimal server with aborted optional capabilities excludes them from active score denominator")
    void testMinimalServer_AllOptionalCapabilitiesAborted_ExcludesFromDenominator() {
        ValidationRun run = createSampleRun("PASSED");

        List<ValidationTestResult> testResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            boolean isCore = mapping.requiredCapabilities().contains("core") ||
                    (mapping.requiredCapabilities().size() == 1 && mapping.requiredCapabilities().contains("core"));
            if (isCore) {
                testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
            } else {
                testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "ABORTED"));
            }
        }

        ValidationHttpExchange exchange = createExchange(
                "https://scim.example.com/v2/ServiceProviderConfig",
                200,
                "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig\"],\"changePassword\":{\"supported\":false}}"
        );

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(exchange));

        // Core tests all passed, aborted capabilities must NOT penalize score
        assertThat(scorecard.coreScore()).isEqualTo(100);
        assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.EMERALD);
        assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(0);
        assertThat(scorecard.compliantCapabilitiesCount()).isEqualTo(0);
        assertThat(scorecard.excludedRequirementsCount()).isGreaterThan(0);
        assertThat(scorecard.publishEligible()).isTrue();

        // Check that optional capabilities are listed as UNSUPPORTED
        for (CapabilityStatus cs : scorecard.capabilities()) {
            assertThat(cs.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            assertThat(cs.isSupported()).isFalse();
        }
    }

    @Test
    @DisplayName("Proportional credit formula: w_r * (P_r / N_r) with MUST=3, SHOULD=2, MAY=1")
    void testProportionalCredit_MustWeight3_ShouldWeight2_MayWeight1() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);

        SpecRequirement rMust = new SpecRequirement(
                "REQ-MUST", "7644", "3.1", "", "MUST", "Must Req", "", "core", "tested");
        SpecRequirement rShould = new SpecRequirement(
                "REQ-SHOULD", "7644", "3.2", "", "SHOULD", "Should Req", "", "core", "tested");
        SpecRequirement rMay = new SpecRequirement(
                "REQ-MAY", "7644", "3.3", "", "MAY", "May Req", "", "core", "tested");

        Map<String, SpecRequirement> reqMap = Map.of(
                "REQ-MUST", rMust,
                "REQ-SHOULD", rShould,
                "REQ-MAY", rMay
        );
        when(mockCatalog.getRequirements()).thenReturn(reqMap);

        // REQ-MUST mapped to T1 and T2
        when(mockCatalog.getTestsForRequirement("REQ-MUST")).thenReturn(List.of("T1", "T2"));
        // REQ-SHOULD mapped to T3
        when(mockCatalog.getTestsForRequirement("REQ-SHOULD")).thenReturn(List.of("T3"));
        // REQ-MAY mapped to T4
        when(mockCatalog.getTestsForRequirement("REQ-MAY")).thenReturn(List.of("T4"));

        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }

        ComplianceScoreService service = new ComplianceScoreService(mockCatalog);

        // T1 passes, T2 fails -> REQ-MUST earned = 3 * (1/2) = 1.5
        // T3 passes -> REQ-SHOULD earned = 2 * (1/1) = 2.0
        // T4 fails -> REQ-MAY earned = 1 * (0/1) = 0.0
        // Total earned = 3.5. Total weight = 3 + 2 + 1 = 6.0.
        // Score = round(100 * 3.5 / 6.0) = round(58.33) = 58%
        List<ValidationTestResult> testResults = List.of(
                createTestResult("T1", "T1: Test 1", "SUCCESS"),
                createTestResult("T2", "T2: Test 2", "FAILED"),
                createTestResult("T3", "T3: Test 3", "SUCCESS"),
                createTestResult("T4", "T4: Test 4", "FAILED")
        );

        ValidationRun run = createSampleRun("PASSED");
        ComplianceScorecardView scorecard = service.computeScorecard(run, testResults, Collections.emptyList());

        assertThat(scorecard.coreScore()).isEqualTo(58);
        assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.ORANGE);
        assertThat(scorecard.publishEligible()).isTrue();

        assertThat(scorecard.mustBreakdown().earnedPoints()).isEqualTo(1.5);
        assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(3.0);
        assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(50);

        assertThat(scorecard.shouldBreakdown().earnedPoints()).isEqualTo(2.0);
        assertThat(scorecard.shouldBreakdown().totalPoints()).isEqualTo(2.0);
        assertThat(scorecard.shouldBreakdown().conformancePercent()).isEqualTo(100);

        assertThat(scorecard.mayBreakdown().earnedPoints()).isEqualTo(0.0);
        assertThat(scorecard.mayBreakdown().totalPoints()).isEqualTo(1.0);
        assertThat(scorecard.mayBreakdown().conformancePercent()).isEqualTo(0);
    }

    @Test
    @DisplayName("5 colour-gradient stops map deterministically across all boundary thresholds")
    void test5ColourGradientStops_BoundaryConditions() {
        assertThat(ColourGradient.forScore(100)).isEqualTo(ColourGradient.EMERALD);
        assertThat(ColourGradient.forScore(95)).isEqualTo(ColourGradient.EMERALD);
        assertThat(ColourGradient.EMERALD.getStartColor()).isEqualTo("#10b981");
        assertThat(ColourGradient.EMERALD.getEndColor()).isEqualTo("#059669");
        assertThat(ColourGradient.EMERALD.isPublishable()).isTrue();

        assertThat(ColourGradient.forScore(94)).isEqualTo(ColourGradient.TEAL_GREEN);
        assertThat(ColourGradient.forScore(85)).isEqualTo(ColourGradient.TEAL_GREEN);
        assertThat(ColourGradient.TEAL_GREEN.getStartColor()).isEqualTo("#22c55e");
        assertThat(ColourGradient.TEAL_GREEN.getEndColor()).isEqualTo("#0d9488");
        assertThat(ColourGradient.TEAL_GREEN.isPublishable()).isTrue();

        assertThat(ColourGradient.forScore(84)).isEqualTo(ColourGradient.AMBER);
        assertThat(ColourGradient.forScore(70)).isEqualTo(ColourGradient.AMBER);
        assertThat(ColourGradient.AMBER.getStartColor()).isEqualTo("#f59e0b");
        assertThat(ColourGradient.AMBER.getEndColor()).isEqualTo("#d97706");
        assertThat(ColourGradient.AMBER.isPublishable()).isTrue();

        assertThat(ColourGradient.forScore(69)).isEqualTo(ColourGradient.ORANGE);
        assertThat(ColourGradient.forScore(50)).isEqualTo(ColourGradient.ORANGE);
        assertThat(ColourGradient.ORANGE.getStartColor()).isEqualTo("#f97316");
        assertThat(ColourGradient.ORANGE.getEndColor()).isEqualTo("#ea580c");
        assertThat(ColourGradient.ORANGE.isPublishable()).isTrue();

        assertThat(ColourGradient.forScore(49)).isEqualTo(ColourGradient.RED);
        assertThat(ColourGradient.forScore(0)).isEqualTo(ColourGradient.RED);
        assertThat(ColourGradient.RED.getStartColor()).isEqualTo("#ef4444");
        assertThat(ColourGradient.RED.getEndColor()).isEqualTo("#dc2626");
        assertThat(ColourGradient.RED.isPublishable()).isFalse();
    }

    @Test
    @DisplayName("Publish eligibility requires status in {PASSED, FAILED} and score >= 50%")
    void testPublishEligibility_ThresholdAndStatus() {
        ValidationRun runPassed50 = createSampleRun("PASSED");
        ValidationRun runFailed50 = createSampleRun("FAILED");
        ValidationRun runFailed49 = createSampleRun("FAILED");
        ValidationRun runRunning95 = createSampleRun("RUNNING");
        ValidationRun runError95 = createSampleRun("ERROR");

        // Helper mock scorecard
        ComplianceScorecardView card50 = createMockScorecard(50, "PASSED");
        ComplianceScorecardView card49 = createMockScorecard(49, "FAILED");
        ComplianceScorecardView card95 = createMockScorecard(95, "RUNNING");

        assertThat(scoreService.isEligibleForPublish(card50, runPassed50)).isTrue();
        assertThat(scoreService.isEligibleForPublish(card50, runFailed50)).isTrue();
        assertThat(scoreService.isEligibleForPublish(card49, runFailed49)).isFalse();
        assertThat(scoreService.isEligibleForPublish(card95, runRunning95)).isFalse();
        assertThat(scoreService.isEligibleForPublish(card95, runError95)).isFalse();
    }

    @Test
    @DisplayName("changePassword capability is discovered from /ServiceProviderConfig exchange")
    void testChangePasswordDiscoveryFromExchange() {
        ValidationRun run = createSampleRun("PASSED");

        ValidationHttpExchange exTrue = createExchange(
                "https://example.com/scim/v2/ServiceProviderConfig",
                200,
                "{\"changePassword\":{\"supported\":true}}"
        );
        ComplianceScorecardView cardTrue = scoreService.computeScorecard(run, Collections.emptyList(), List.of(exTrue));
        Optional<CapabilityStatus> cpTrue = cardTrue.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst();
        assertThat(cpTrue).isPresent();
        assertThat(cpTrue.get().status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
        assertThat(cpTrue.get().isSupported()).isFalse();

        ValidationHttpExchange exFalse = createExchange(
                "https://example.com/scim/v2/ServiceProviderConfig",
                200,
                "{\"changePassword\":{\"supported\":false}}"
        );
        ComplianceScorecardView cardFalse = scoreService.computeScorecard(run, Collections.emptyList(), List.of(exFalse));
        Optional<CapabilityStatus> cpFalse = cardFalse.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst();
        assertThat(cpFalse).isPresent();
        assertThat(cpFalse.get().status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
        assertThat(cpFalse.get().isSupported()).isFalse();

        // Empty exchanges fallback to UNSUPPORTED
        ComplianceScorecardView cardEmpty = scoreService.computeScorecard(run, Collections.emptyList(), Collections.emptyList());
        Optional<CapabilityStatus> cpEmpty = cardEmpty.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst();
        assertThat(cpEmpty).isPresent();
        assertThat(cpEmpty.get().status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
    }

    /** One result per changePassword test: the first gets firstStatus, all others restStatus. */
    private List<ValidationTestResult> changePasswordResults(
            List<de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping> tests, String firstStatus, String restStatus) {
        List<ValidationTestResult> results = new java.util.ArrayList<>();
        for (int i = 0; i < tests.size(); i++) {
            results.add(createTestResult(tests.get(i).testId(), tests.get(i).displayName(), i == 0 ? firstStatus : restStatus));
        }
        return results;
    }

    /** The tests of the changePassword capability, taken from the real catalog mappings. */
    private java.util.List<de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping> changePasswordTests() {
        var tests = catalogService.getAllTestMappings().values().stream()
                .filter(m -> "changePassword".equals(m.capability()))
                .sorted(java.util.Comparator.comparing(de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping::testId))
                .toList();
        assertThat(tests).hasSizeGreaterThanOrEqualTo(2);
        return tests;
    }

    @Test
    @DisplayName("changePassword capability is evaluated from mapped test results when available")
    void testChangePasswordEvaluatedFromTestResults() {
        ValidationRun run = createSampleRun("PASSED");
        var changePasswordTests = changePasswordTests();

        // 1. All pass -> SUPPORTED_COMPLIANT
        List<ValidationTestResult> resultsPass = changePasswordResults(changePasswordTests, "SUCCESS", "SUCCESS");
        ComplianceScorecardView cardPass = scoreService.computeScorecard(run, resultsPass, Collections.emptyList());
        CapabilityStatus cpPass = cardPass.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpPass.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
        assertThat(cpPass.isSupported()).isTrue();
        assertThat(cpPass.passRate()).isEqualTo(100.0);
        assertThat(cpPass.totalTests()).isEqualTo(changePasswordTests.size());
        assertThat(cpPass.passedTests()).isEqualTo(changePasswordTests.size());
        assertThat(cpPass.failedTests()).isZero();

        // 2. Failure -> SUPPORTED_PARTIAL
        List<ValidationTestResult> resultsFail = changePasswordResults(changePasswordTests, "FAILED", "FAILED");
        ComplianceScorecardView cardFail = scoreService.computeScorecard(run, resultsFail, Collections.emptyList());
        CapabilityStatus cpFail = cardFail.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpFail.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_PARTIAL);
        assertThat(cpFail.isSupported()).isTrue();
        assertThat(cpFail.passRate()).isZero();
        assertThat(cpFail.totalTests()).isEqualTo(changePasswordTests.size());
        assertThat(cpFail.passedTests()).isZero();
        assertThat(cpFail.failedTests()).isEqualTo(changePasswordTests.size());

        // 3. Aborted / empty execution -> UNSUPPORTED
        List<ValidationTestResult> resultsAbort = changePasswordResults(changePasswordTests, "ABORTED", "ABORTED");
        ComplianceScorecardView cardAbort = scoreService.computeScorecard(run, resultsAbort, Collections.emptyList());
        CapabilityStatus cpAbort = cardAbort.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpAbort.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
        assertThat(cpAbort.isSupported()).isFalse();
        assertThat(cpAbort.totalTests()).isEqualTo(changePasswordTests.size());
        assertThat(cpAbort.abortedTests()).isEqualTo(changePasswordTests.size());
    }

    @Test
    @DisplayName("Capability with mixed pass and fail is marked SUPPORTED_PARTIAL")
    void testSupportedPartialCapability() {
        ValidationRun run = createSampleRun("PASSED");
        List<ValidationTestResult> testResults = new ArrayList<>();

        List<String> filterTestIds = catalogService.getTestsForCapability("filter");
        assertThat(filterTestIds).isNotEmpty();

        // Make first filter test pass, second fail, rest abort
        testResults.add(createTestResult(filterTestIds.get(0), filterTestIds.get(0) + ": Pass", "SUCCESS"));
        if (filterTestIds.size() > 1) {
            testResults.add(createTestResult(filterTestIds.get(1), filterTestIds.get(1) + ": Fail", "FAILED"));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());
        Optional<CapabilityStatus> filterStatus = scorecard.capabilities().stream()
                .filter(c -> "filter".equals(c.capability())).findFirst();

        assertThat(filterStatus).isPresent();
        assertThat(filterStatus.get().status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_PARTIAL);
        assertThat(filterStatus.get().isSupported()).isTrue();
        assertThat(filterStatus.get().passRate()).isGreaterThan(0.0).isLessThan(100.0);
    }

    @Test
    @DisplayName("Per-RFC summaries cover RFC 7643, 7644, 9865, and 9967")
    void testPerRfcSummariesComputed() {
        ValidationRun run = createSampleRun("PASSED");
        List<ValidationTestResult> testResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());
        Map<String, RfcSectionSummary> summaries = scorecard.rfcSummaries();

        assertThat(summaries).containsKeys("7643", "7644", "9865", "9967");
        for (String rfc : List.of("7643", "7644", "9865", "9967")) {
            long inCatalog = catalogService.getRequirements().values().stream().filter(r -> rfc.equals(r.rfc())).count();
            assertThat(summaries.get(rfc).totalRequirements()).isEqualTo((int) inCatalog);
        }

        for (RfcSectionSummary s : summaries.values()) {
            assertThat(s.rfcTitle()).isNotBlank();
            assertThat(s.conformancePercent()).isEqualTo(100);
        }
    }

    @Test
    @DisplayName("Dispositions: na without executed tests is EXCLUDED_CAPABILITY; unassigned/gap/tested without tests are UNTESTED and stay in the denominator")
    void testDispositions_NaExcluded_UnassignedAndGapScoredLikeTested() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        Map<String, SpecRequirement> reqMap = new LinkedHashMap<>();
        for (String disposition : List.of("tested", "unassigned", "gap", "na", "optional")) {
            String id = "RFC7644-3-" + disposition;
            reqMap.put(id, new SpecRequirement(id, "7644", "3", "", "MUST", "Req " + disposition, "", "core", disposition));
            when(mockCatalog.getTestsForRequirement(id)).thenReturn(List.of());
        }
        String passId = "RFC7644-3-pass";
        reqMap.put(passId, new SpecRequirement(passId, "7644", "3", "", "MUST", "Req pass", "", "core", "unassigned"));
        when(mockCatalog.getTestsForRequirement(passId)).thenReturn(List.of(passId));
        when(mockCatalog.getTestMapping(passId)).thenReturn(Optional.of(new TestSpecMapping(
                passId, passId + ": passes", "Spec", 1, List.of("core"), List.of(passId))));
        when(mockCatalog.getRequirements()).thenReturn(reqMap);
        for (String id : reqMap.keySet()) {
            when(mockCatalog.getRequirement(id)).thenReturn(Optional.of(reqMap.get(id)));
        }
        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }

        ComplianceScoreService customService = new ComplianceScoreService(mockCatalog);
        ComplianceScorecardView scorecard = customService.computeScorecard(
                createSampleRun("PASSED"),
                List.of(createTestResult(passId, passId + ": passes", "SUCCESS")),
                Collections.emptyList());

        Map<String, RequirementTraceResult> byId = new HashMap<>();
        scorecard.requirementMatrix().forEach(r -> byId.put(r.id(), r));
        assertThat(byId.get("RFC7644-3-na").status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(byId.get("RFC7644-3-na").inActiveScope()).isFalse();
        for (String disposition : List.of("tested", "unassigned", "gap", "optional")) {
            RequirementTraceResult trace = byId.get("RFC7644-3-" + disposition);
            assertThat(trace.status()).as(disposition).isEqualTo("UNTESTED");
            assertThat(trace.inActiveScope()).as(disposition).isTrue();
        }
        assertThat(byId.get(passId).status()).isEqualTo("COMPLIANT");

        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(1);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(4);
        // 5 MUST requirements in scope (pass, tested, unassigned, gap, optional) = 15 points, 3 earned
        assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(15.0);
        assertThat(scorecard.coreScore()).isEqualTo(20);

        // Core-only conformance: tested/unassigned/gap take part, optional and na do not
        assertThat(ComplianceScoreService.isCoreOnlyRequirement(reqMap.get("RFC7644-3-gap"))).isTrue();
        assertThat(ComplianceScoreService.isCoreOnlyRequirement(reqMap.get("RFC7644-3-unassigned"))).isTrue();
        assertThat(ComplianceScoreService.isCoreOnlyRequirement(reqMap.get("RFC7644-3-tested"))).isTrue();
        assertThat(ComplianceScoreService.isCoreOnlyRequirement(reqMap.get("RFC7644-3-optional"))).isFalse();
        assertThat(ComplianceScoreService.isCoreOnlyRequirement(reqMap.get("RFC7644-3-na"))).isFalse();
        assertThat(customService.computeCoreOnlyTotalPoints(scorecard)).isEqualTo(12.0);
    }

    @Test
    @DisplayName("Core requirement whose only mapped test is blocked by an inactive capability becomes EXCLUDED_CAPABILITY and is excluded from core coverage denominator")
    void testCoreRequirementBlockedByInactiveCapability_ExcludedFromDenominatorAndNotUntested() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);

        SpecRequirement corePass = new SpecRequirement(
                "REQ-CORE-PASS", "7644", "3.1", "", "MUST", "Core Passing Req", "", "core", "tested");
        SpecRequirement coreBlocked1 = new SpecRequirement(
                "REQ-CORE-BLOCKED-1", "7644", "3.14", "", "MUST", "Core Blocked by ETag 1", "", "core", "tested");
        SpecRequirement coreBlocked2 = new SpecRequirement(
                "REQ-CORE-BLOCKED-2", "7644", "3.14", "", "MUST", "Core Blocked by ETag 2", "", "core", "tested");

        Map<String, SpecRequirement> reqMap = new LinkedHashMap<>();
        reqMap.put(corePass.id(), corePass);
        reqMap.put(coreBlocked1.id(), coreBlocked1);
        reqMap.put(coreBlocked2.id(), coreBlocked2);
        when(mockCatalog.getRequirements()).thenReturn(reqMap);
        when(mockCatalog.getRequirement("REQ-CORE-PASS")).thenReturn(Optional.of(corePass));
        when(mockCatalog.getRequirement("REQ-CORE-BLOCKED-1")).thenReturn(Optional.of(coreBlocked1));
        when(mockCatalog.getRequirement("REQ-CORE-BLOCKED-2")).thenReturn(Optional.of(coreBlocked2));

        when(mockCatalog.getTestsForRequirement("REQ-CORE-PASS")).thenReturn(List.of("T_CORE"));
        when(mockCatalog.getTestsForRequirement("REQ-CORE-BLOCKED-1")).thenReturn(List.of("T_ETAG_1"));
        when(mockCatalog.getTestsForRequirement("REQ-CORE-BLOCKED-2")).thenReturn(List.of("T_ETAG_2"));

        TestSpecMapping coreMapping = new TestSpecMapping(
                "T_CORE", "T_CORE: Core test", "Spec", 1, List.of("core"), List.of("REQ-CORE-PASS"));
        TestSpecMapping etagMapping1 = new TestSpecMapping(
                "T_ETAG_1", "T_ETAG_1: ETag test 1", "Spec", 2, List.of("etag"), List.of("REQ-CORE-BLOCKED-1"));
        TestSpecMapping etagMapping2 = new TestSpecMapping(
                "T_ETAG_2", "T_ETAG_2: ETag test 2", "Spec", 3, List.of("etag"), List.of("REQ-CORE-BLOCKED-2"));
        assertThat(etagMapping1.requiredCapabilities()).containsExactly("etag");
        assertThat(etagMapping1.specRefs()).containsExactly("REQ-CORE-BLOCKED-1");

        when(mockCatalog.getTestMapping("T_CORE")).thenReturn(Optional.of(coreMapping));
        when(mockCatalog.getTestMapping("T_ETAG_1")).thenReturn(Optional.of(etagMapping1));
        when(mockCatalog.getTestMapping("T_ETAG_2")).thenReturn(Optional.of(etagMapping2));

        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            if ("etag".equals(cap)) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(List.of("T_ETAG_1", "T_ETAG_2", "T_ETAG_PASS"));
            } else {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
            }
        }

        ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
        ValidationRun run = createSampleRun("PASSED");
        List<ValidationTestResult> testResults = List.of(
                createTestResult("T_CORE", "T_CORE: Core test", "SUCCESS"),
                createTestResult("T_ETAG_1", "T_ETAG_1: ETag test 1", "ABORTED"),
                createTestResult("T_ETAG_2", "T_ETAG_2: ETag test 2", "ABORTED")
        );

        ComplianceScorecardView scorecard = service.computeScorecard(run, testResults, Collections.emptyList());

        Map<String, RequirementTraceResult> matrixById = new LinkedHashMap<>();
        for (RequirementTraceResult r : scorecard.requirementMatrix()) {
            matrixById.put(r.id(), r);
        }

        RequirementTraceResult blockedTrace1 = matrixById.get("REQ-CORE-BLOCKED-1");
        assertThat(blockedTrace1.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(blockedTrace1.inActiveScope()).isFalse();

        RequirementTraceResult blockedTrace2 = matrixById.get("REQ-CORE-BLOCKED-2");
        assertThat(blockedTrace2.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(blockedTrace2.inActiveScope()).isFalse();

        assertThat(scorecard.untestedRequirementsCount()).isZero();
        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(2);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(1);
        assertThat(scorecard.coreScore()).isEqualTo(100);
        // Without capActive exclusion, only 1/3 (33%) of core requirements would count as executed (< 50% threshold)
        assertThat(scorecard.publishEligible()).isTrue();
        assertThat(service.isEligibleForPublish(scorecard, run)).isTrue();

        // Contrasting check: when "etag" IS active (T_ETAG_PASS succeeds), while T_ETAG_1 and T_ETAG_2 are still ABORTED,
        // REQ-CORE-BLOCKED-1 and REQ-CORE-BLOCKED-2 become UNTESTED (1/3 = 33% coverage -> ineligible).
        ComplianceScorecardView etagActiveScorecard = service.computeScorecard(run, List.of(
                createTestResult("T_CORE", "T_CORE: Core test", "SUCCESS"),
                createTestResult("T_ETAG_PASS", "T_ETAG_PASS: ETag active", "SUCCESS"),
                createTestResult("T_ETAG_1", "T_ETAG_1: ETag test 1", "ABORTED"),
                createTestResult("T_ETAG_2", "T_ETAG_2: ETag test 2", "ABORTED")
        ), Collections.emptyList());
        assertThat(etagActiveScorecard.untestedRequirementsCount()).isEqualTo(2);
        assertThat(etagActiveScorecard.excludedRequirementsCount()).isZero();
        assertThat(etagActiveScorecard.publishEligible()).isFalse();
    }

    @Test
    @DisplayName("meetsMinimumCoverage and isEligibleForPublish exclude EXCLUDED_CAPABILITY core rows from denominator")
    void testMeetsMinimumCoverage_ExcludesExcludedCapabilityCoreRows() {
        ValidationRun passedRun = createSampleRun("PASSED");

        // 1 executed core requirement (COMPLIANT) + 4 EXCLUDED_CAPABILITY core requirements (using real non-na IDs)
        // Without !"EXCLUDED_CAPABILITY".equals(r.status()) in meetsMinimumCoverage, coverage would be 1/5 = 20% (< 50% and < 80%)
        List<RequirementTraceResult> matrixWithExcluded = List.of(
                new RequirementTraceResult("RFC7644-4-R1", "7644", "4", "Req 1", "MUST", 3, "core",
                        true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("DSC_01")),
                new RequirementTraceResult("RFC7644-4-R2", "7644", "4", "Req 2", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("DSC_05")),
                new RequirementTraceResult("RFC7644-4-R3", "7644", "4", "Req 3", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("DSC_10")),
                new RequirementTraceResult("RFC7644-2-R1", "7644", "2", "Req 4", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("SEC_01")),
                new RequirementTraceResult("RFC7644-3.1-R1", "7644", "3.1", "Req 5", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("DSC_13"))
        );

        ComplianceScorecardView scorecard = new ComplianceScorecardView(
                UUID.randomUUID(), "Test", "http://example.com", OffsetDateTime.now(), "PASSED",
                100, ColourGradient.EMERALD, true, null, null, null, null,
                Collections.emptyList(), 0, 0, 10,
                5, 1, 4, 0,
                Collections.emptyMap(), matrixWithExcluded
        );

        assertThat(scoreService.isEligibleForPublish(scorecard, passedRun)).isTrue();

        // Conversely, if those 4 core rows were UNTESTED instead of EXCLUDED_CAPABILITY, coverage is 1/5 = 20% -> ineligible
        List<RequirementTraceResult> matrixWithUntested = List.of(
                new RequirementTraceResult("RFC7644-4-R1", "7644", "4", "Req 1", "MUST", 3, "core",
                        true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("DSC_01")),
                new RequirementTraceResult("RFC7644-4-R2", "7644", "4", "Req 2", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("DSC_05")),
                new RequirementTraceResult("RFC7644-4-R3", "7644", "4", "Req 3", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("DSC_10")),
                new RequirementTraceResult("RFC7644-2-R1", "7644", "2", "Req 4", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("SEC_01")),
                new RequirementTraceResult("RFC7644-3.1-R1", "7644", "3.1", "Req 5", "MUST", 3, "core",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("DSC_13"))
        );
        ComplianceScorecardView scorecardUntested = new ComplianceScorecardView(
                UUID.randomUUID(), "Test", "http://example.com", OffsetDateTime.now(), "PASSED",
                100, ColourGradient.EMERALD, false, null, null, null, null,
                Collections.emptyList(), 0, 0, 10,
                5, 1, 0, 4,
                Collections.emptyMap(), matrixWithUntested
        );
        assertThat(scoreService.isEligibleForPublish(scorecardUntested, passedRun)).isFalse();
    }

    @Test
    @DisplayName("Composite capability requirement whose mapped tests are all blocked by an inactive capability becomes EXCLUDED_CAPABILITY and not UNTESTED")
    void testCompositeCapabilityRequirementBlockedByInactiveCapability_BecomesExcludedNotUntested() {
        ValidationRun run = createSampleRun("PASSED");

        // Custom catalog: when search is active (SRH_01 passes) and filter is inactive (FLT_17 and FLT_38 abort,
        // both requiring ["filter", "search"]), RFC7644-3.4.3-R1 (capability: "search", mapped only to FLT_17 and FLT_38)
        // becomes EXCLUDED_CAPABILITY and NOT UNTESTED.
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        SpecRequirement rfc343R1 = new SpecRequirement(
                "RFC7644-3.4.3-R1", "7644", "3.4.3", "", "MUST", "POST /.search query", "", "search", "optional");
        SpecRequirement searchOther = new SpecRequirement(
                "RFC7644-3.4.3-R2", "7644", "3.4.3", "", "MUST", "POST /.search other", "", "search", "optional");
        when(mockCatalog.getRequirements()).thenReturn(Map.of(
                "RFC7644-3.4.3-R1", rfc343R1,
                "RFC7644-3.4.3-R2", searchOther
        ));
        when(mockCatalog.getTestsForRequirement("RFC7644-3.4.3-R1")).thenReturn(List.of("FLT_17", "FLT_38"));
        when(mockCatalog.getTestsForRequirement("RFC7644-3.4.3-R2")).thenReturn(List.of("SRH_01"));
        when(mockCatalog.getTestMapping("FLT_17")).thenReturn(Optional.of(new TestSpecMapping(
                "FLT_17", "FLT_17: Search groups", "Spec", 1, List.of("filter", "search"), List.of("RFC7644-3.4.3-R1"))));
        when(mockCatalog.getTestMapping("FLT_38")).thenReturn(Optional.of(new TestSpecMapping(
                "FLT_38", "FLT_38: Search filter", "Spec", 2, List.of("filter", "search"), List.of("RFC7644-3.4.3-R1"))));
        when(mockCatalog.getTestMapping("SRH_01")).thenReturn(Optional.of(new TestSpecMapping(
                "SRH_01", "SRH_01: Search endpoint", "Spec", 3, List.of("search"), List.of("RFC7644-3.4.3-R2"))));

        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            if ("search".equals(cap)) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(List.of("SRH_01", "FLT_17", "FLT_38"));
            } else if ("filter".equals(cap)) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(List.of("FLT_17", "FLT_38", "FLT_PASS"));
            } else {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
            }
        }

        ComplianceScoreService customScoreService = new ComplianceScoreService(mockCatalog);
        ComplianceScorecardView customScorecard = customScoreService.computeScorecard(run, List.of(
                createTestResult("SRH_01", "SRH_01: Search endpoint", "SUCCESS"),
                createTestResult("FLT_17", "FLT_17: Search groups", "ABORTED"),
                createTestResult("FLT_38", "FLT_38: Search filter", "ABORTED")
        ), Collections.emptyList());

        RequirementTraceResult trace343R1 = customScorecard.requirementMatrix().stream()
                .filter(r -> "RFC7644-3.4.3-R1".equals(r.id()))
                .findFirst()
                .orElseThrow();
        assertThat(trace343R1.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(trace343R1.inActiveScope()).isFalse();
        assertThat(customScorecard.untestedRequirementsCount()).isZero();

        // Contrasting check: when "filter" IS active alongside "search" (FLT_PASS succeeds),
        // while FLT_17 and FLT_38 are still ABORTED, RFC7644-3.4.3-R1 becomes UNTESTED.
        ComplianceScorecardView bothActiveScorecard = customScoreService.computeScorecard(run, List.of(
                createTestResult("SRH_01", "SRH_01: Search endpoint", "SUCCESS"),
                createTestResult("FLT_PASS", "FLT_PASS: Filter active", "SUCCESS"),
                createTestResult("FLT_17", "FLT_17: Search groups", "ABORTED"),
                createTestResult("FLT_38", "FLT_38: Search filter", "ABORTED")
        ), Collections.emptyList());

        RequirementTraceResult trace343R1BothActive = bothActiveScorecard.requirementMatrix().stream()
                .filter(r -> "RFC7644-3.4.3-R1".equals(r.id()))
                .findFirst()
                .orElseThrow();
        assertThat(trace343R1BothActive.status()).isEqualTo("UNTESTED");
        assertThat(bothActiveScorecard.untestedRequirementsCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("TASK-58: Requirement with mixed SUCCESS and ABORTED tests is marked PARTIAL and intra-requirement denominator is total mapped tests")
    void testMixedSuccessAndAbortedRequirement_MarkedPartial_DenominatorMaintained() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        SpecRequirement req = new SpecRequirement(
                "REQ-MIXED", "7644", "3.1", "", "MUST", "Mixed Req", "", "core", "tested");

        when(mockCatalog.getRequirements()).thenReturn(Map.of("REQ-MIXED", req));
        when(mockCatalog.getTestsForRequirement("REQ-MIXED")).thenReturn(List.of("T_PASS", "T_ABORT"));
        when(mockCatalog.getTestMapping("T_PASS")).thenReturn(Optional.of(new TestSpecMapping(
                "T_PASS", "Pass", "Spec", 1, List.of("core"), List.of("REQ-MIXED"))));
        when(mockCatalog.getTestMapping("T_ABORT")).thenReturn(Optional.of(new TestSpecMapping(
                "T_ABORT", "Abort", "Spec", 1, List.of("core"), List.of("REQ-MIXED"))));
        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }

        ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
        ValidationRun run = createSampleRun("PASSED");

        List<ValidationTestResult> testResults = List.of(
                createTestResult("T_PASS", "T_PASS", "SUCCESS"),
                createTestResult("T_ABORT", "T_ABORT", "ABORTED")
        );

        ComplianceScorecardView scorecard = service.computeScorecard(run, testResults, Collections.emptyList());
        RequirementTraceResult trace = scorecard.requirementMatrix().get(0);

        // TASK-58: Must be PARTIAL, not COMPLIANT
        assertThat(trace.status()).isEqualTo("PARTIAL");
        // TASK-57: Earned is 3 * (1 / 2) = 1.5, not 3 * (1 / 1) = 3.0
        assertThat(trace.earnedWeight()).isEqualTo(1.5);
        assertThat(scorecard.coreScore()).isEqualTo(50);
        assertThat(scorecard.mustBreakdown().compliantRequirements()).isZero();
        assertThat(scorecard.mustBreakdown().partialRequirements()).isEqualTo(1);
    }

    @Test
    @DisplayName("TASK-57: Untested or aborted active requirements contribute 0.0 earned against fixed denominator")
    void testUntestedRequirement_ContributesToDenominator_EarnsZeroPoints() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        SpecRequirement req1 = new SpecRequirement(
                "REQ-1", "7644", "3.1", "", "MUST", "Req 1", "", "core", "tested");
        SpecRequirement req2 = new SpecRequirement(
                "REQ-2", "7644", "3.2", "", "MUST", "Req 2", "", "core", "tested");

        when(mockCatalog.getRequirements()).thenReturn(Map.of("REQ-1", req1, "REQ-2", req2));
        when(mockCatalog.getTestsForRequirement("REQ-1")).thenReturn(List.of("T1"));
        when(mockCatalog.getTestsForRequirement("REQ-2")).thenReturn(List.of("T2"));
        when(mockCatalog.getTestMapping("T1")).thenReturn(Optional.of(new TestSpecMapping(
                "T1", "T1", "Spec", 1, List.of("core"), List.of("REQ-1"))));
        when(mockCatalog.getTestMapping("T2")).thenReturn(Optional.of(new TestSpecMapping(
                "T2", "T2", "Spec", 1, List.of("core"), List.of("REQ-2"))));
        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }

        ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
        ValidationRun run = createSampleRun("PASSED");

        // T1 passes, T2 is aborted (executedTestsForReq == 0 for REQ-2)
        List<ValidationTestResult> testResults = List.of(
                createTestResult("T1", "T1", "SUCCESS"),
                createTestResult("T2", "T2", "ABORTED")
        );

        ComplianceScorecardView scorecard = service.computeScorecard(run, testResults, Collections.emptyList());

        // Without fixed denominator, REQ-2 would be dropped and score would be 100%.
        // With fixed denominator, REQ-2 weight (3) is included in totalWeight (6), earning 0.0 -> score = 50%.
        assertThat(scorecard.coreScore()).isEqualTo(50);
        assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(6.0);
        assertThat(scorecard.mustBreakdown().earnedPoints()).isEqualTo(3.0);
        assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(50);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(1);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("TASK-61: Capability scoring requires all tests passing and zero aborts for SUPPORTED_COMPLIANT")
    void testCapabilityRequiresAllTestsPassedAndZeroAborted_ForSupportedCompliant() {
        ValidationRun run = createSampleRun("PASSED");
        var changePasswordTests = changePasswordTests();

        // 1. One pass and one abort -> SUPPORTED_PARTIAL
        List<ValidationTestResult> mixedResults = changePasswordResults(changePasswordTests, "SUCCESS", "ABORTED");
        ComplianceScorecardView mixedCard = scoreService.computeScorecard(run, mixedResults, Collections.emptyList());
        CapabilityStatus cpMixed = mixedCard.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpMixed.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_PARTIAL);
        // the pass rate is relative to every mapped test of the capability, not only the executed two
        assertThat(cpMixed.passRate()).isCloseTo(100.0 / changePasswordTests.size(), org.assertj.core.data.Offset.offset(0.01));
        assertThat(cpMixed.isSupported()).isTrue();

        // 2. Both pass -> SUPPORTED_COMPLIANT
        List<ValidationTestResult> allPassResults = changePasswordResults(changePasswordTests, "SUCCESS", "SUCCESS");
        ComplianceScorecardView compliantCard = scoreService.computeScorecard(run, allPassResults, Collections.emptyList());
        CapabilityStatus cpCompliant = compliantCard.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpCompliant.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
        assertThat(cpCompliant.passRate()).isEqualTo(100.0);
        assertThat(cpCompliant.isSupported()).isTrue();
    }

    @Test
    @DisplayName("TASK-62 (a): One MAY failure out of 200+ points caps coreScore at 99 and mayBreakdown at 99 while MUST/SHOULD stay 100")
    void test99PercentCap_OneMayFailure_CapsCoreScoreAndMayBreakdownAt99() {
        ValidationRun run = createSampleRun("FAILED");

        // 1. Real catalog: fail one test of a single-test MAY requirement (weight 1) in an otherwise perfect run
        String mayTestId = catalogService.getAllMappings().stream()
                .filter(m -> catalogService.getRequirement(m.testId()).orElseThrow().isMayOrOptional())
                .filter(m -> catalogService.getRequirement(m.testId()).orElseThrow().isCore())
                .map(TestSpecMapping::testId)
                .findFirst().orElseThrow();
        double totalWeight = catalogService.getRequirements().values().stream().mapToDouble(SpecRequirement::getWeight).sum();
        List<ValidationTestResult> realResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            String status = mayTestId.equals(mapping.testId()) ? "FAILED" : "SUCCESS";
            realResults.add(createTestResult(mapping.testId(), mapping.displayName(), status));
        }

        ComplianceScorecardView realCard = scoreService.computeScorecard(run, realResults, Collections.emptyList());
        assertThat(realCard.coreScore()).isEqualTo(cappedScore(totalWeight - 1, totalWeight));
        assertThat(realCard.mustBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(realCard.shouldBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(realCard.formattedNormativePoints())
                .isEqualTo(ComplianceScorecardView.formatPointsPair(totalWeight - 1, totalWeight));

        // 2. Custom catalog where MAY total is 200 and 1 MAY fails (199/200 = 99.5% -> rounds to 100, capped at 99)
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        Map<String, SpecRequirement> reqMap = new LinkedHashMap<>();
        SpecRequirement rMust = new SpecRequirement("R-MUST", "7644", "3.1", "", "MUST", "Must", "", "core", "tested");
        SpecRequirement rShould = new SpecRequirement("R-SHOULD", "7644", "3.2", "", "SHOULD", "Should", "", "core", "tested");
        reqMap.put(rMust.id(), rMust);
        reqMap.put(rShould.id(), rShould);
        when(mockCatalog.getTestsForRequirement("R-MUST")).thenReturn(List.of("TM"));
        when(mockCatalog.getTestsForRequirement("R-SHOULD")).thenReturn(List.of("TS"));

        List<ValidationTestResult> customResults = new ArrayList<>();
        customResults.add(createTestResult("TM", "TM: Must", "SUCCESS"));
        customResults.add(createTestResult("TS", "TS: Should", "SUCCESS"));
        for (int i = 1; i <= 200; i++) {
            String id = "R-MAY-" + i;
            String tid = "TMAY_" + i;
            reqMap.put(id, new SpecRequirement(id, "7644", "3.3", "", "MAY", "May " + i, "", "core", "tested"));
            when(mockCatalog.getTestsForRequirement(id)).thenReturn(List.of(tid));
            customResults.add(createTestResult(tid, tid + ": May", i == 200 ? "FAILED" : "SUCCESS"));
        }
        when(mockCatalog.getRequirements()).thenReturn(reqMap);
        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }

        ComplianceScoreService customService = new ComplianceScoreService(mockCatalog);
        ComplianceScorecardView customCard = customService.computeScorecard(run, customResults, Collections.emptyList());
        assertThat(customCard.coreScore()).isEqualTo(99);
        assertThat(customCard.mayBreakdown().conformancePercent()).isEqualTo(99);
        assertThat(customCard.mustBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(customCard.shouldBreakdown().conformancePercent()).isEqualTo(100);
    }

    @Test
    @DisplayName("TASK-62 (b): One SHOULD failure caps coreScore below 100 and shouldBreakdown below 100")
    void test99PercentCap_OneShouldFailure_CapsCoreScoreAt99AndShouldBelow100() {
        ValidationRun run = createSampleRun("FAILED");

        // Fail one test of a SHOULD requirement (weight 2) in an otherwise perfect run
        String shouldTestId = catalogService.getAllMappings().stream()
                .filter(m -> catalogService.getRequirement(m.testId()).orElseThrow().isShould())
                .map(TestSpecMapping::testId)
                .findFirst().orElseThrow();
        double totalWeight = catalogService.getRequirements().values().stream().mapToDouble(SpecRequirement::getWeight).sum();
        List<ValidationTestResult> results = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            String status = shouldTestId.equals(mapping.testId()) ? "FAILED" : "SUCCESS";
            results.add(createTestResult(mapping.testId(), mapping.displayName(), status));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, results, Collections.emptyList());
        assertThat(scorecard.coreScore()).isEqualTo(cappedScore(totalWeight - 2, totalWeight));
        assertThat(scorecard.shouldBreakdown().conformancePercent()).isLessThan(100);
        assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(scorecard.mayBreakdown().conformancePercent()).isEqualTo(100);
        assertThat(scorecard.conformanceTierLabel()).isNotEqualTo("Certified RFC Compliant");
    }

    @Test
    @DisplayName("TASK-62 (c): RfcSectionSummary 99% cap when earned < total and Math.round would be 100")
    void test99PercentCap_RfcSectionSummary_CappedAt99WhenEarnedLessThanTotal() {
        ValidationRun run = createSampleRun("FAILED");

        // Find a test mapping to a single RFC 7644 requirement where failing that 1 test loses <= 1.0 point
        String targetTestId = catalogService.getAllMappings().stream()
                .filter(m -> m.specRefs().size() == 1)
                .filter(m -> {
                    SpecRequirement req = catalogService.getRequirement(m.specRefs().get(0)).orElse(null);
                    int testCount = catalogService.getTestsForRequirement(m.specRefs().get(0)).size();
                    return req != null && "7644".equals(req.rfc()) && testCount > 0 && ((double) req.getWeight() / testCount) <= 1.0;
                })
                .map(TestSpecMapping::testId)
                .findFirst()
                .orElseThrow();

        List<ValidationTestResult> results = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            String status = targetTestId.equals(mapping.testId()) ? "FAILED" : "SUCCESS";
            results.add(createTestResult(mapping.testId(), mapping.displayName(), status));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, results, Collections.emptyList());
        RfcSectionSummary rfc7644Summary = scorecard.rfcSummaries().get("7644");
        assertThat(rfc7644Summary).isNotNull();
        assertThat(rfc7644Summary.earnedPoints()).isLessThan(rfc7644Summary.totalPoints());
        assertThat(Math.round((100.0 * rfc7644Summary.earnedPoints()) / rfc7644Summary.totalPoints())).isEqualTo(100L);
        assertThat(rfc7644Summary.conformancePercent()).isEqualTo(99);
    }

    @Test
    @DisplayName("TASK-62 (d): NormativeBreakdown.of caps 429.9/430.0 at 99% and keeps 430.0/430.0 at 100%")
    void test99PercentCap_NormativeBreakdownOf_429_9Of430Is99_And430Of430Is100() {
        NormativeBreakdown partial = NormativeBreakdown.of("MUST", 3, 143, 142, 1, 0, 429.9, 430.0);
        assertThat(partial.conformancePercent()).isEqualTo(99);

        NormativeBreakdown perfect = NormativeBreakdown.of("MUST", 3, 143, 143, 0, 0, 430.0, 430.0);
        assertThat(perfect.conformancePercent()).isEqualTo(100);
    }

    @Test
    @DisplayName("TASK-59 (e): Aborted optional (MAY-level) core requirements do not penalize coreCoveragePercent")
    void testTask59_OptionalDispositionCoreRequirementAbort_DoesNotPenalizeCoreCoverage() {
        ValidationRun run = createSampleRun("PARTIAL");

        // One MAY-level core requirement aborts (MAY requirements are optional sub-features)
        String abortedOptionalCoreTest = catalogService.getAllMappings().stream()
                .filter(m -> {
                    SpecRequirement req = catalogService.getRequirement(m.testId()).orElseThrow();
                    return req.isCore() && req.isMayOrOptional();
                })
                .map(TestSpecMapping::testId)
                .findFirst().orElseThrow();
        List<ValidationTestResult> results = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            String status = abortedOptionalCoreTest.equals(mapping.testId()) ? "ABORTED" : "SUCCESS";
            results.add(createTestResult(mapping.testId(), mapping.displayName(), status));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, results, Collections.emptyList());
        assertThat(scorecard.coreScore()).isEqualTo(100);
        assertThat(scorecard.coreCoveragePercent()).isEqualTo(100);
        assertThat(scoreService.isEligibleForPublish(scorecard, run)).isEqualTo(scorecard.publishEligible());
    }

    @Test
    @DisplayName("TASK-60 (f): SKIPPED test result status is treated identically to ABORTED in ComplianceScoreService")
    void testSkippedStatus_TreatedIdenticallyToAbortedInScoring() {
        ValidationRun run = createSampleRun("PARTIAL");

        List<ValidationTestResult> abortedResults = new ArrayList<>();
        List<ValidationTestResult> skippedResults = new ArrayList<>();
        List<String> filterTests = catalogService.getTestsForCapability("filter");
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            boolean isFilter = filterTests.contains(mapping.testId());
            abortedResults.add(createTestResult(mapping.testId(), mapping.displayName(), isFilter ? "ABORTED" : "SUCCESS"));
            skippedResults.add(createTestResult(mapping.testId(), mapping.displayName(), isFilter ? "SKIPPED" : "SUCCESS"));
        }

        ComplianceScorecardView abortedCard = scoreService.computeScorecard(run, abortedResults, Collections.emptyList());
        ComplianceScorecardView skippedCard = scoreService.computeScorecard(run, skippedResults, Collections.emptyList());

        assertThat(skippedCard.coreScore()).isEqualTo(abortedCard.coreScore());
        assertThat(skippedCard.coreOnlyScore()).isEqualTo(abortedCard.coreOnlyScore());
        assertThat(skippedCard.activeRequirementsCount()).isEqualTo(abortedCard.activeRequirementsCount());
        assertThat(skippedCard.excludedRequirementsCount()).isEqualTo(abortedCard.excludedRequirementsCount());
        assertThat(skippedCard.untestedRequirementsCount()).isEqualTo(abortedCard.untestedRequirementsCount());

        CapabilityStatus filterAborted = abortedCard.capabilities().stream()
                .filter(c -> "filter".equals(c.capability())).findFirst().orElseThrow();
        CapabilityStatus filterSkipped = skippedCard.capabilities().stream()
                .filter(c -> "filter".equals(c.capability())).findFirst().orElseThrow();
        assertThat(filterSkipped.status()).isEqualTo(filterAborted.status());
        assertThat(filterSkipped.abortedTests()).isEqualTo(filterAborted.abortedTests());
    }

    @Test
    @DisplayName("(g): extractTestId in ComplianceScoreService and SpecCatalogService extracts requirement-id test ids")
    void testExtractTestId_RequirementIds() {
        List<String> expectedIds = catalogService.getAllMappings().stream().map(TestSpecMapping::testId).limit(10).toList();
        assertThat(expectedIds).isNotEmpty();
        for (String id : expectedIds) {
            assertThat(ComplianceScoreService.extractTestId(id)).isEqualTo(id);
            assertThat(ComplianceScoreService.extractTestId(id + ": Feature description")).isEqualTo(id);
            assertThat(catalogService.getTestMapping(id)).isPresent();
            assertThat(catalogService.getTestMapping(id + ": Feature description")).isPresent();
        }
        assertThat(ComplianceScoreService.extractTestId("RFC7643-2.3.6-1a2b3c: Label")).isEqualTo("RFC7643-2.3.6-1a2b3c");
        assertThat(ComplianceScoreService.extractTestId("RFC7643-2.3.6-1a2b3c")).isEqualTo("RFC7643-2.3.6-1a2b3c");
    }

    @Test
    @DisplayName("TASK-63 (h): computeCoreOnlyScore, computeCoreOnlyEarnedPoints, computeCoreOnlyTotalPoints use the core-scored denominator and 99% cap")
    void testCoreOnlyScore_CoreDenominator_And99PercentCap() {
        ValidationRun run = createSampleRun("PASSED");

        // 1. Full passing run: all core scored requirements earn their full weight
        List<ValidationTestResult> allPass = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            allPass.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
        }
        double coreTotal = coreWeight();
        ComplianceScorecardView fullCard = scoreService.computeScorecard(run, allPass, Collections.emptyList());
        assertThat(scoreService.computeCoreOnlyTotalPoints(fullCard)).isEqualTo(coreTotal);
        assertThat(scoreService.computeCoreOnlyEarnedPoints(fullCard)).isEqualTo(coreTotal);
        assertThat(scoreService.computeCoreOnlyScore(fullCard)).isEqualTo(100);
        assertThat(fullCard.coreOnlyTotalPoints()).isEqualTo(coreTotal);
        assertThat(fullCard.coreOnlyEarnedPoints()).isEqualTo(coreTotal);
        assertThat(fullCard.coreOnlyScore()).isEqualTo(100);

        // 2. Partial credit on a core-tested requirement whose loss alone rounds to 100% (< 0.5% of the core total)
        String targetCoreTestId = catalogService.getAllMappings().stream()
                .filter(m -> m.specRefs().size() == 1)
                .filter(m -> {
                    SpecRequirement req = catalogService.getRequirement(m.specRefs().get(0)).orElse(null);
                    int testCount = catalogService.getTestsForRequirement(m.specRefs().get(0)).size();
                    return ComplianceScoreService.isCoreOnlyRequirement(req)
                            && testCount > 0
                            && (100.0 * req.getWeight() / testCount) / coreTotal < 0.5;
                })
                .map(TestSpecMapping::testId)
                .findFirst()
                .orElseThrow();

        List<ValidationTestResult> oneCoreSmallLoss = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            String status = targetCoreTestId.equals(mapping.testId()) ? "FAILED" : "SUCCESS";
            oneCoreSmallLoss.add(createTestResult(mapping.testId(), mapping.displayName(), status));
        }
        ComplianceScorecardView cappedCoreCard = scoreService.computeScorecard(run, oneCoreSmallLoss, Collections.emptyList());
        assertThat(scoreService.computeCoreOnlyTotalPoints(cappedCoreCard)).isEqualTo(coreTotal);
        assertThat(scoreService.computeCoreOnlyEarnedPoints(cappedCoreCard)).isGreaterThan(coreTotal * 0.995).isLessThan(coreTotal);
        // without the cap this would round to 100; the cap must hold it at 99
        assertThat((int) Math.round(100.0 * cappedCoreCard.coreOnlyEarnedPoints() / coreTotal)).isEqualTo(100);
        int expectedCappedScore = cappedScore(cappedCoreCard.coreOnlyEarnedPoints(), coreTotal);
        assertThat(expectedCappedScore).isEqualTo(99);
        assertThat(scoreService.computeCoreOnlyScore(cappedCoreCard)).isEqualTo(expectedCappedScore).isLessThan(100);
        assertThat(cappedCoreCard.coreOnlyScore()).isEqualTo(expectedCappedScore);
    }

    @Test
    @DisplayName("Policy 3.3 (F3): Conformance Tier distinguishes 'Certified RFC Compliant' vs 'Excellent Conformance'")
    void testConformanceTierLabel_CertifiedVsExcellent() {
        NormativeBreakdown mustZeroFailed = NormativeBreakdown.of("MUST", 3, 129, 129, 0, 0, 387.0, 387.0);
        NormativeBreakdown mustOneFailed = NormativeBreakdown.of("MUST", 3, 129, 128, 0, 1, 384.0, 387.0);

        assertThat(ComplianceScorecardView.computeConformanceTierLabel(100, 100, mustZeroFailed))
                .isEqualTo("Certified RFC Compliant");
        assertThat(ComplianceScorecardView.computeConformanceTierLabel(99, 100, mustZeroFailed))
                .isEqualTo("Excellent Conformance");
        assertThat(ComplianceScorecardView.computeConformanceTierLabel(95, 100, mustZeroFailed))
                .isEqualTo("Excellent Conformance");
        assertThat(ComplianceScorecardView.computeConformanceTierLabel(100, 99, mustZeroFailed))
                .isEqualTo("Excellent Conformance");
        assertThat(ComplianceScorecardView.computeConformanceTierLabel(100, 100, mustOneFailed))
                .isEqualTo("Excellent Conformance");
        assertThat(ComplianceScorecardView.computeConformanceTierLabel(90, 100, mustZeroFailed))
                .isEqualTo("Good");
    }

    @Test
    @DisplayName("F4: Capability passRate, coreCoveragePercent, and formattedNormativePoints respect 99% cap")
    void testRoundingSitesCappedAt99_CapabilityPassRate_CoreCoverage_FormattedPoints() {
        // 1. Capability passRate: 199 / 200 = 99.5% -> capped at 99.0 so SUPPORTED_PARTIAL never shows 100%
        CapabilityStatus partialCap = CapabilityStatus.of(
                "filter", "Filtering", "RFC 7644 §3.4.2.2", CapabilitySupportLevel.SUPPORTED_PARTIAL,
                200, 200, 199, 1, 0);
        assertThat(partialCap.passRate()).isEqualTo(99.0);

        CapabilityStatus fullCap = CapabilityStatus.of(
                "filter", "Filtering", "RFC 7644 §3.4.2.2", CapabilitySupportLevel.SUPPORTED_COMPLIANT,
                200, 200, 200, 0, 0);
        assertThat(fullCap.passRate()).isEqualTo(100.0);

        // 2. Formatted points pair never rounds fractional earned points up to total
        assertThat(ComplianceScorecardView.formatPointsPair(431.0, 431.0)).isEqualTo("431 / 431");
        assertThat(ComplianceScorecardView.formatPointsPair(430.0, 431.0)).isEqualTo("430 / 431");
        assertThat(ComplianceScorecardView.formatPointsPair(430.6, 431.0)).isEqualTo("430.6 / 431");
        assertThat(ComplianceScorecardView.formatPointsPair(430.99, 431.0)).isEqualTo("430.9 / 431");

        // 3. coreCoveragePercent: 199 / 200 testable core requirements executed -> 99.5% capped at 99%
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        Map<String, SpecRequirement> reqMap = new LinkedHashMap<>();
        List<ValidationTestResult> results = new ArrayList<>();
        for (int i = 1; i <= 200; i++) {
            String reqId = "REQ-CORE-" + i;
            String tid = "TC_" + i;
            SpecRequirement req = new SpecRequirement(reqId, "7644", "3.1", "", "MUST", "Core " + i, "", "core", "tested");
            reqMap.put(reqId, req);
            when(mockCatalog.getRequirement(reqId)).thenReturn(Optional.of(req));
            when(mockCatalog.getTestsForRequirement(reqId)).thenReturn(List.of(tid));
            if (i < 200) {
                results.add(createTestResult(tid, tid + ": Core", "SUCCESS"));
            }
        }
        when(mockCatalog.getRequirements()).thenReturn(reqMap);
        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
        }
        ComplianceScoreService customService = new ComplianceScoreService(mockCatalog);
        ComplianceScorecardView card = customService.computeScorecard(createSampleRun("PARTIAL"), results, Collections.emptyList());
        assertThat(card.coreCoveragePercent()).isEqualTo(99);
    }

    @Test
    @DisplayName("F5: Multi-test core requirement excludes tests whose required optional capability is inactive from totalTestsForReq")
    void testMultiTestCoreRequirement_InactiveCapabilityTestExcludedFromDenominator() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        SpecRequirement coreReq = new SpecRequirement(
                "REQ-CORE-MULTI", "7644", "3.4.2", "", "MUST", "Core Query Req", "", "core", "tested");

        when(mockCatalog.getRequirements()).thenReturn(Map.of("REQ-CORE-MULTI", coreReq));
        when(mockCatalog.getRequirement("REQ-CORE-MULTI")).thenReturn(Optional.of(coreReq));
        when(mockCatalog.getTestsForRequirement("REQ-CORE-MULTI")).thenReturn(List.of("T_CORE", "T_FILTER"));
        when(mockCatalog.getTestMapping("T_CORE")).thenReturn(Optional.of(new TestSpecMapping(
                "T_CORE", "T_CORE: Pagination test", "Spec", 1, List.of("core"), List.of("REQ-CORE-MULTI"))));
        when(mockCatalog.getTestMapping("T_FILTER")).thenReturn(Optional.of(new TestSpecMapping(
                "T_FILTER", "T_FILTER: Filter test", "Spec", 2, List.of("filter"), List.of("REQ-CORE-MULTI"))));

        for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
            if ("filter".equals(cap)) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(List.of("T_FILTER"));
            } else {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
            }
        }

        ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
        ValidationRun run = createSampleRun("PASSED");

        // T_CORE succeeds, T_FILTER aborts because filter capability is unsupported/inactive
        List<ValidationTestResult> results = List.of(
                createTestResult("T_CORE", "T_CORE: Pagination test", "SUCCESS"),
                createTestResult("T_FILTER", "T_FILTER: Filter test", "ABORTED")
        );

        ComplianceScorecardView scorecard = service.computeScorecard(run, results, Collections.emptyList());
        RequirementTraceResult trace = scorecard.requirementMatrix().get(0);

        // T_FILTER is excluded from effectiveTestIds because "filter" capability is inactive
        assertThat(trace.totalTests()).isEqualTo(1);
        assertThat(trace.executedTests()).isEqualTo(1);
        assertThat(trace.passedTests()).isEqualTo(1);
        assertThat(trace.status()).isEqualTo("COMPLIANT");
        assertThat(trace.earnedWeight()).isEqualTo(3.0);
        assertThat(scorecard.coreScore()).isEqualTo(100);
    }

    private ComplianceScorecardView createMockScorecard(int score, String status) {
        return new ComplianceScorecardView(
                UUID.randomUUID(), "Test", "http://example.com", OffsetDateTime.now(), status,
                score, ColourGradient.forScore(score),
                ("PASSED".equals(status) || "FAILED".equals(status)) && score >= 50,
                null, null, null, null,
                Collections.emptyList(), 0, 0, 10,
                159, 100, 0, 10,
                Collections.emptyMap(), Collections.emptyList()
        );
    }
}
