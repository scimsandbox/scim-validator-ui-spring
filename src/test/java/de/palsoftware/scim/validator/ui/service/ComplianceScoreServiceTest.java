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

        assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(157);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(147);
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(8);
        assertThat(scorecard.excludedRequirementsCount()).isEqualTo(2);

        assertThat(scorecard.getScoreBadgeText()).isEqualTo("100%");
        assertThat(scorecard.getCapabilityBadgeText()).isEqualTo("10/10 caps");
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
        assertThat(summaries.get("7643").totalRequirements()).isEqualTo(48);
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
        assertThat(scorecard.untestedRequirementsCount()).isEqualTo(8);
        assertThat(scorecard.activeRequirementsCount()).isEqualTo(147);
        assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(157);
    }

    private ComplianceScorecardView createMockScorecard(int score, String status) {
        return new ComplianceScorecardView(
                UUID.randomUUID(), "Test", "http://example.com", OffsetDateTime.now(), status,
                score, ColourGradient.forScore(score),
                ("PASSED".equals(status) || "FAILED".equals(status)) && score >= 50,
                null, null, null, null,
                Collections.emptyList(), 0, 0, 10,
                157, 100, 0, 10,
                Collections.emptyMap(), Collections.emptyList()
        );
    }
}
