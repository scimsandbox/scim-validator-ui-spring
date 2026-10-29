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
        catalogService = new SpecCatalogService(new PathMatchingResourcePatternResolver());
        catalogService.init();
        scoreService = new ComplianceScoreService(catalogService, new ObjectMapper());
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

        assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(159);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(157);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(0);
        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(2);

        assertThat(scorecard.getScoreBadgeText()).isEqualTo("100%");
        assertThat(scorecard.getCapabilityBadgeText()).isEqualTo("10/10 caps");

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
            boolean isCore = mapping.requiredCapabilities().contains("none") ||
                    (mapping.requiredCapabilities().size() == 1 && mapping.requiredCapabilities().contains("none"));
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
                "REQ-MUST", "7644", "3.1", "Must Req", "MUST", "none", "response", "tested", "");
        SpecRequirement rShould = new SpecRequirement(
                "REQ-SHOULD", "7644", "3.2", "Should Req", "SHOULD", "none", "response", "tested", "");
        SpecRequirement rMay = new SpecRequirement(
                "REQ-MAY", "7644", "3.3", "May Req", "MAY", "none", "response", "tested", "");

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
        assertThat(cpTrue.get().status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
        assertThat(cpTrue.get().isSupported()).isTrue();

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

    @Test
    @DisplayName("changePassword capability is evaluated from mapped test results when available")
    void testChangePasswordEvaluatedFromTestResults() {
        ValidationRun run = createSampleRun("PASSED");

        // 1. All pass -> SUPPORTED_COMPLIANT
        List<ValidationTestResult> resultsPass = List.of(
                createTestResult("USR_25", "USR_25: Password update", "SUCCESS"),
                createTestResult("PAT_32", "PAT_32: Password change via PATCH", "SUCCESS")
        );
        ComplianceScorecardView cardPass = scoreService.computeScorecard(run, resultsPass, Collections.emptyList());
        CapabilityStatus cpPass = cardPass.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpPass.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
        assertThat(cpPass.isSupported()).isTrue();
        assertThat(cpPass.passRate()).isEqualTo(100.0);
        assertThat(cpPass.totalTests()).isEqualTo(2);
        assertThat(cpPass.passedTests()).isEqualTo(2);
        assertThat(cpPass.failedTests()).isZero();

        // 2. Failure -> SUPPORTED_PARTIAL
        List<ValidationTestResult> resultsFail = List.of(
                createTestResult("USR_25", "USR_25: Password update", "FAILED"),
                createTestResult("PAT_32", "PAT_32: Password change via PATCH", "FAILED")
        );
        ComplianceScorecardView cardFail = scoreService.computeScorecard(run, resultsFail, Collections.emptyList());
        CapabilityStatus cpFail = cardFail.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpFail.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_PARTIAL);
        assertThat(cpFail.isSupported()).isTrue();
        assertThat(cpFail.passRate()).isZero();
        assertThat(cpFail.totalTests()).isEqualTo(2);
        assertThat(cpFail.passedTests()).isZero();
        assertThat(cpFail.failedTests()).isEqualTo(2);

        // 3. Aborted / empty execution -> UNSUPPORTED
        List<ValidationTestResult> resultsAbort = List.of(
                createTestResult("USR_25", "USR_25: Password update", "ABORTED"),
                createTestResult("PAT_32", "PAT_32: Password change via PATCH", "ABORTED")
        );
        ComplianceScorecardView cardAbort = scoreService.computeScorecard(run, resultsAbort, Collections.emptyList());
        CapabilityStatus cpAbort = cardAbort.capabilities().stream()
                .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
        assertThat(cpAbort.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
        assertThat(cpAbort.isSupported()).isFalse();
        assertThat(cpAbort.totalTests()).isEqualTo(2);
        assertThat(cpAbort.abortedTests()).isEqualTo(2);
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
        assertThat(summaries.get("7643").totalRequirements()).isEqualTo(50);
        assertThat(summaries.get("7644").totalRequirements()).isEqualTo(96);
        assertThat(summaries.get("9865").totalRequirements()).isEqualTo(8);
        assertThat(summaries.get("9967").totalRequirements()).isEqualTo(5);

        for (RfcSectionSummary s : summaries.values()) {
            assertThat(s.rfcTitle()).isNotBlank();
            assertThat(s.conformancePercent()).isEqualTo(100);
        }
    }

    @Test
    @DisplayName("Non-API-observable catalog items with disposition: na and zero executed tests are classified as EXCLUDED_CAPABILITY")
    void testNonApiObservableDispositionNa_ClassifiedAsExcludedCapability() {
        ValidationRun run = createSampleRun("PASSED");
        List<ValidationTestResult> testResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
        }

        ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());

        // Verify that RFC7643-9.2-R1 and RFC7644-7.2-R1 are classified as EXCLUDED_CAPABILITY in the requirement matrix
        Map<String, RequirementTraceResult> matrixById = new HashMap<>();
        for (RequirementTraceResult r : scorecard.requirementMatrix()) {
            matrixById.put(r.id(), r);
        }

        assertThat(matrixById).containsKey("RFC7643-9.2-R1");
        RequirementTraceResult rfc7643 = matrixById.get("RFC7643-9.2-R1");
        assertThat(rfc7643.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(rfc7643.inActiveScope()).isFalse();
        assertThat(rfc7643.executedTests()).isZero();

        assertThat(matrixById).containsKey("RFC7644-7.2-R1");
        RequirementTraceResult rfc7644 = matrixById.get("RFC7644-7.2-R1");
        assertThat(rfc7644.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(rfc7644.inActiveScope()).isFalse();
        assertThat(rfc7644.executedTests()).isZero();

        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(2);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(0);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(157);
        assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(159);
    }

    @Test
    @DisplayName("Core requirement whose only mapped test is blocked by an inactive capability becomes EXCLUDED_CAPABILITY and is excluded from core coverage denominator")
    void testCoreRequirementBlockedByInactiveCapability_ExcludedFromDenominatorAndNotUntested() {
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);

        SpecRequirement corePass = new SpecRequirement(
                "REQ-CORE-PASS", "7644", "3.1", "Core Passing Req", "MUST", "none", "response", "tested", "");
        SpecRequirement coreBlocked1 = new SpecRequirement(
                "REQ-CORE-BLOCKED-1", "7644", "3.14", "Core Blocked by ETag 1", "MUST", "none", "response", "tested", "");
        SpecRequirement coreBlocked2 = new SpecRequirement(
                "REQ-CORE-BLOCKED-2", "7644", "3.14", "Core Blocked by ETag 2", "MUST", "none", "response", "tested", "");

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
                "T_CORE", "T_CORE: Core test", "Spec", 1, List.of("none"), List.of("REQ-CORE-PASS"));
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
                new RequirementTraceResult("RFC7644-4-R1", "7644", "4", "Req 1", "MUST", 3, "none",
                        true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("DSC_01")),
                new RequirementTraceResult("RFC7644-4-R2", "7644", "4", "Req 2", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("DSC_05")),
                new RequirementTraceResult("RFC7644-4-R3", "7644", "4", "Req 3", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("DSC_10")),
                new RequirementTraceResult("RFC7644-2-R1", "7644", "2", "Req 4", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "EXCLUDED_CAPABILITY", List.of("SEC_01")),
                new RequirementTraceResult("RFC7644-3.1-R1", "7644", "3.1", "Req 5", "MUST", 3, "none",
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
                new RequirementTraceResult("RFC7644-4-R1", "7644", "4", "Req 1", "MUST", 3, "none",
                        true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("DSC_01")),
                new RequirementTraceResult("RFC7644-4-R2", "7644", "4", "Req 2", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("DSC_05")),
                new RequirementTraceResult("RFC7644-4-R3", "7644", "4", "Req 3", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("DSC_10")),
                new RequirementTraceResult("RFC7644-2-R1", "7644", "2", "Req 4", "MUST", 3, "none",
                        false, 1, 0, 0, 0, 1, 0.0, "UNTESTED", List.of("SEC_01")),
                new RequirementTraceResult("RFC7644-3.1-R1", "7644", "3.1", "Req 5", "MUST", 3, "none",
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

        // 1. Real catalog: search is active (PAG_07 passes) while filter is inactive (all filter tests abort,
        // including FLT_33 and FLT_40 which require ["filter", "search"]).
        // RFC7644-3.4.2.1-R1 (capability: "search", mapped only to FLT_33 and FLT_40) must become EXCLUDED_CAPABILITY.
        List<ValidationTestResult> realResults = new ArrayList<>();
        for (TestSpecMapping mapping : catalogService.getAllMappings()) {
            if (mapping.requiredCapabilities().contains("filter")) {
                realResults.add(createTestResult(mapping.testId(), mapping.displayName(), "ABORTED"));
            } else {
                realResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
            }
        }
        ComplianceScorecardView realScorecard = scoreService.computeScorecard(run, realResults, Collections.emptyList());

        RequirementTraceResult rfc3421R1 = realScorecard.requirementMatrix().stream()
                .filter(r -> "RFC7644-3.4.2.1-R1".equals(r.id()))
                .findFirst()
                .orElseThrow();
        assertThat(rfc3421R1.capability()).isEqualTo("search");
        assertThat(rfc3421R1.status()).isEqualTo("EXCLUDED_CAPABILITY");
        assertThat(rfc3421R1.inActiveScope()).isFalse();
        assertThat(realScorecard.untestedRequirementsCount()).isZero();

        // 2. Custom catalog: when search is active (SRH_01 passes) and filter is inactive (FLT_17 and FLT_38 abort,
        // both requiring ["filter", "search"]), RFC7644-3.4.3-R1 (capability: "search", mapped only to FLT_17 and FLT_38)
        // becomes EXCLUDED_CAPABILITY and NOT UNTESTED.
        SpecCatalogService mockCatalog = mock(SpecCatalogService.class);
        SpecRequirement rfc343R1 = new SpecRequirement(
                "RFC7644-3.4.3-R1", "7644", "3.4.3", "POST /.search query", "MUST", "search", "response", "optional", "");
        SpecRequirement searchOther = new SpecRequirement(
                "RFC7644-3.4.3-R2", "7644", "3.4.3", "POST /.search other", "MUST", "search", "response", "optional", "");
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
