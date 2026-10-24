package de.palsoftware.scim.validator.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.palsoftware.scim.validator.ui.model.ValidationHttpExchange;
import de.palsoftware.scim.validator.ui.model.ValidationRun;
import de.palsoftware.scim.validator.ui.model.ValidationTestResult;
import de.palsoftware.scim.validator.ui.model.spec.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.time.OffsetDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Empirical and adversarial challenge test suite for Milestone 2:
 * Mathematical boundaries, zero tests, all aborted, 5 colour-gradient brackets,
 * rounding precision, and publish eligibility threshold.
 */
public class ComplianceScoreServiceChallengerTest {

    private static SpecCatalogService catalogService;
    private static ComplianceScoreService scoreService;

    @BeforeAll
    static void setUp() {
        catalogService = new SpecCatalogService(new PathMatchingResourcePatternResolver());
        catalogService.init();
        scoreService = new ComplianceScoreService(catalogService, new ObjectMapper());
    }

    private static ValidationRun createRun(String status) {
        ValidationRun run = new ValidationRun();
        try {
            java.lang.reflect.Field idField = ValidationRun.class.getDeclaredField("id");
            idField.setAccessible(true);
            idField.set(run, UUID.randomUUID());
        } catch (Exception ignored) {}
        run.setName("Challenger Test Run");
        run.setTargetUrl("https://scim.example.com/v2");
        run.setStatus(status);
        run.setExecutedAt(OffsetDateTime.now());
        return run;
    }

    private static ValidationTestResult createTestResult(String testId, String displayName, String status) {
        ValidationTestResult tr = new ValidationTestResult();
        tr.setTestIdentifier(testId);
        tr.setDisplayName(displayName);
        tr.setTestName(displayName);
        tr.setStatus(status);
        return tr;
    }

    private static ValidationHttpExchange createExchange(String url, int status, String body) {
        ValidationHttpExchange ex = new ValidationHttpExchange();
        ex.setUrl(url);
        ex.setResponseStatus(status);
        ex.setResponseBody(body);
        return ex;
    }

    // =========================================================================
    // 1. 5 COLOUR-GRADIENT BRACKET BOUNDARIES (0..100 & Out of Range)
    // =========================================================================
    @Nested
    @DisplayName("1. Colour-Gradient Bracket Boundaries")
    class ColourGradientBoundaryTests {

        @Test
        @DisplayName("Every integer score in [0, 100] maps to the strictly correct ColourGradient")
        void testAll101GradientScores() {
            for (int s = 0; s <= 100; s++) {
                ColourGradient g = ColourGradient.forScore(s);
                if (s >= 95) {
                    assertThat(g).as("Score %d must map to EMERALD", s).isEqualTo(ColourGradient.EMERALD);
                    assertThat(g.getStartColor()).isEqualTo("#10b981");
                    assertThat(g.getEndColor()).isEqualTo("#059669");
                    assertThat(g.isPublishable()).isTrue();
                } else if (s >= 85) {
                    assertThat(g).as("Score %d must map to TEAL_GREEN", s).isEqualTo(ColourGradient.TEAL_GREEN);
                    assertThat(g.getStartColor()).isEqualTo("#22c55e");
                    assertThat(g.getEndColor()).isEqualTo("#0d9488");
                    assertThat(g.isPublishable()).isTrue();
                } else if (s >= 70) {
                    assertThat(g).as("Score %d must map to AMBER", s).isEqualTo(ColourGradient.AMBER);
                    assertThat(g.getStartColor()).isEqualTo("#f59e0b");
                    assertThat(g.getEndColor()).isEqualTo("#d97706");
                    assertThat(g.isPublishable()).isTrue();
                } else if (s >= 50) {
                    assertThat(g).as("Score %d must map to ORANGE", s).isEqualTo(ColourGradient.ORANGE);
                    assertThat(g.getStartColor()).isEqualTo("#f97316");
                    assertThat(g.getEndColor()).isEqualTo("#ea580c");
                    assertThat(g.isPublishable()).isTrue();
                } else {
                    assertThat(g).as("Score %d must map to RED", s).isEqualTo(ColourGradient.RED);
                    assertThat(g.getStartColor()).isEqualTo("#ef4444");
                    assertThat(g.getEndColor()).isEqualTo("#dc2626");
                    assertThat(g.isPublishable()).isFalse();
                }
            }
        }

        @Test
        @DisplayName("Exact boundary transitions: 95/94, 85/84, 70/69, 50/49")
        void testExactBoundaryTransitions() {
            // Emerald vs Teal/Green
            assertThat(ColourGradient.forScore(95)).isEqualTo(ColourGradient.EMERALD);
            assertThat(ColourGradient.forScore(94)).isEqualTo(ColourGradient.TEAL_GREEN);

            // Teal/Green vs Amber
            assertThat(ColourGradient.forScore(85)).isEqualTo(ColourGradient.TEAL_GREEN);
            assertThat(ColourGradient.forScore(84)).isEqualTo(ColourGradient.AMBER);

            // Amber vs Orange
            assertThat(ColourGradient.forScore(70)).isEqualTo(ColourGradient.AMBER);
            assertThat(ColourGradient.forScore(69)).isEqualTo(ColourGradient.ORANGE);

            // Orange vs Red (Publishability critical threshold!)
            assertThat(ColourGradient.forScore(50)).isEqualTo(ColourGradient.ORANGE);
            assertThat(ColourGradient.forScore(49)).isEqualTo(ColourGradient.RED);
            assertThat(ColourGradient.forScore(50).isPublishable()).isTrue();
            assertThat(ColourGradient.forScore(49).isPublishable()).isFalse();
        }

        @Test
        @DisplayName("Out of range scores (negative and >100) degrade gracefully")
        void testOutOfRangeScores() {
            assertThat(ColourGradient.forScore(-100)).isEqualTo(ColourGradient.RED);
            assertThat(ColourGradient.forScore(-1)).isEqualTo(ColourGradient.RED);
            assertThat(ColourGradient.forScore(101)).isEqualTo(ColourGradient.EMERALD);
            assertThat(ColourGradient.forScore(500)).isEqualTo(ColourGradient.EMERALD);
        }

        @Test
        @DisplayName("cssLinearGradient formats properly for all 5 brackets")
        void testCssLinearGradientFormat() {
            assertThat(ColourGradient.EMERALD.cssLinearGradient())
                    .isEqualTo("linear-gradient(135deg, #10b981 0%, #059669 100%)");
            assertThat(ColourGradient.TEAL_GREEN.cssLinearGradient())
                    .isEqualTo("linear-gradient(135deg, #22c55e 0%, #0d9488 100%)");
            assertThat(ColourGradient.AMBER.cssLinearGradient())
                    .isEqualTo("linear-gradient(135deg, #f59e0b 0%, #d97706 100%)");
            assertThat(ColourGradient.ORANGE.cssLinearGradient())
                    .isEqualTo("linear-gradient(135deg, #f97316 0%, #ea580c 100%)");
            assertThat(ColourGradient.RED.cssLinearGradient())
                    .isEqualTo("linear-gradient(135deg, #ef4444 0%, #dc2626 100%)");
        }
    }

    // =========================================================================
    // 2. PUBLISH ELIGIBILITY THRESHOLDS & STATUS MATRIX
    // =========================================================================
    @Nested
    @DisplayName("2. Publish Eligibility Matrix (Threshold & Status)")
    class PublishEligibilityTests {

        @ParameterizedTest(name = "Status={0}, Score={1} -> Eligible={2}")
        @CsvSource({
                "PASSED, 50, true",
                "PASSED, 49, false",
                "PASSED, 100, true",
                "PASSED, 0, false",
                "FAILED, 50, true",
                "FAILED, 49, false",
                "FAILED, 85, true",
                "FAILED, 0, false",
                "RUNNING, 100, false",
                "RUNNING, 50, false",
                "RUNNING, 49, false",
                "ERROR, 100, false",
                "ERROR, 50, false",
                "ERROR, 0, false",
                "QUEUED, 100, false",
                "CANCELED, 100, false",
                "UNKNOWN, 100, false"
        })
        void testPublishEligibilityCombinations(String status, int score, boolean expectedEligible) {
            ValidationRun run = createRun(status);
            ComplianceScorecardView scorecard = createStubScorecard(score, status);

            boolean serviceResult = scoreService.isEligibleForPublish(scorecard, run);
            assertThat(serviceResult).isEqualTo(expectedEligible);
            assertThat(scorecard.publishEligible()).isEqualTo(expectedEligible);
        }

        @Test
        @DisplayName("Case insensitivity in status check (passed, failed, running, error)")
        void testCaseInsensitivityInPublishCheck() {
            ValidationRun runPassedLower = createRun("passed");
            ComplianceScorecardView card50 = createStubScorecard(50, "passed");
            assertThat(scoreService.isEligibleForPublish(card50, runPassedLower)).isTrue();

            ValidationRun runFailedLower = createRun("failed");
            ComplianceScorecardView card50F = createStubScorecard(50, "failed");
            assertThat(scoreService.isEligibleForPublish(card50F, runFailedLower)).isTrue();

            ValidationRun runRunningLower = createRun("running");
            ComplianceScorecardView card100R = createStubScorecard(100, "running");
            assertThat(scoreService.isEligibleForPublish(card100R, runRunningLower)).isFalse();
        }

        @Test
        @DisplayName("Ineligibility reasons are descriptive and accurately distinguished")
        void testIneligibilityReasons() {
            // Running run
            ValidationRun runRunning = createRun("RUNNING");
            ComplianceScorecardView cardRunning = scoreService.computeScorecard(runRunning, Collections.emptyList(), Collections.emptyList());
            assertThat(cardRunning.publishEligible()).isFalse();
            assertThat(cardRunning.publishIneligibilityReason()).isEqualTo("Validation run is still running.");

            // Error run
            ValidationRun runError = createRun("ERROR");
            ComplianceScorecardView cardError = scoreService.computeScorecard(runError, Collections.emptyList(), Collections.emptyList());
            assertThat(cardError.publishEligible()).isFalse();
            assertThat(cardError.publishIneligibilityReason()).isEqualTo("Validation run encountered an execution error.");

            // Unknown status run
            ValidationRun runQueued = createRun("QUEUED");
            ComplianceScorecardView cardQueued = scoreService.computeScorecard(runQueued, Collections.emptyList(), Collections.emptyList());
            assertThat(cardQueued.publishEligible()).isFalse();
            assertThat(cardQueued.publishIneligibilityReason()).contains("QUEUED");

            // Terminal status but score below 50%
            ValidationRun runPassed49 = createRun("PASSED");
            ComplianceScorecardView card49 = scoreService.computeScorecard(runPassed49, Collections.emptyList(), Collections.emptyList());
            assertThat(card49.publishEligible()).isFalse();
            assertThat(card49.publishIneligibilityReason())
                    .contains("below the minimum 50% publishing threshold");
        }

        @Test
        @DisplayName("Null safety: null run, null scorecard, null status")
        void testNullSafetyInPublishCheck() {
            ComplianceScorecardView card = createStubScorecard(100, "PASSED");
            ValidationRun run = createRun(null);

            assertThat(scoreService.isEligibleForPublish(null, run)).isFalse();
            assertThat(scoreService.isEligibleForPublish(card, null)).isFalse();
            assertThat(scoreService.isEligibleForPublish(card, run)).isFalse();
        }
    }

    // =========================================================================
    // 3. ZERO TESTS & EMPTY / NULL INPUTS (DIVISION BY ZERO PROTECTION)
    // =========================================================================
    @Nested
    @DisplayName("3. Zero Tests & Division-by-Zero Edge Cases")
    class ZeroTestsEdgeCases {

        @Test
        @DisplayName("Null test results, null run, null exchanges do not throw NPE or ArithmeticException")
        void testCompletelyNullInputs() {
            assertThatCode(() -> {
                ComplianceScorecardView scorecard = scoreService.computeScorecard(null, null, null);
                assertThat(scorecard).isNotNull();
                assertThat(scorecard.coreScore()).isEqualTo(0);
                assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.RED);
                assertThat(scorecard.publishEligible()).isFalse();
                assertThat(scorecard.activeRequirementsCount()).isEqualTo(0);
                assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(0);
                assertThat(scorecard.compliantCapabilitiesCount()).isEqualTo(0);
                assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(0);
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Zero test results returns score=0, RED, 0 active requirements, zero division avoided")
        void testEmptyTestResultsList() {
            ValidationRun run = createRun("PASSED");
            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, Collections.emptyList(), Collections.emptyList());

            assertThat(scorecard.coreScore()).isEqualTo(0);
            assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.RED);
            assertThat(scorecard.publishEligible()).isFalse();
            assertThat(scorecard.activeRequirementsCount()).isEqualTo(0);
            assertThat(scorecard.untestedRequirementsCount()).isGreaterThan(0);
            assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(0);

            // Normative breakdowns default to 0% conformance when totalPoints is 0
            assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(0.0);
            assertThat(scorecard.mustBreakdown().earnedPoints()).isEqualTo(0.0);
            assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(0);
        }

        @Test
        @DisplayName("Test results with null fields or unknown statuses are handled safely")
        void testResultsWithNullOrMalformedFields() {
            ValidationRun run = createRun("PASSED");
            List<ValidationTestResult> results = new ArrayList<>();

            // 1. Result with all null fields
            ValidationTestResult rNull = new ValidationTestResult();
            results.add(rNull);

            // 2. Result with empty or whitespace testId
            results.add(createTestResult("   ", "   ", "SUCCESS"));

            // 3. Result with unknown status ("SKIPPED", "BLOCKED", null)
            results.add(createTestResult("DSC_01", "DSC_01: Config", "SKIPPED"));
            results.add(createTestResult("USER_01", "USER_01: User", null));

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, results, Collections.emptyList());
            assertThat(scorecard.coreScore()).isEqualTo(0);
            assertThat(scorecard.activeRequirementsCount()).isEqualTo(0);
        }
    }

    // =========================================================================
    // 4. ALL-ABORTED TEST SUITE (EXCLUSION & DENOMINATOR RESISTANCE)
    // =========================================================================
    @Nested
    @DisplayName("4. All-Aborted Edge Cases")
    class AllAbortedEdgeCases {

        @Test
        @DisplayName("When 100% of mapped tests are ABORTED, active scope is 0, score=0, no division by zero")
        void testEntireCatalogAllAborted() {
            ValidationRun run = createRun("PASSED");
            List<ValidationTestResult> testResults = new ArrayList<>();

            for (TestSpecMapping mapping : catalogService.getAllMappings()) {
                testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "ABORTED"));
            }

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());

            // Executed tests = 0 everywhere -> active scope = 0 requirements
            assertThat(scorecard.coreScore()).isEqualTo(0);
            assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.RED);
            assertThat(scorecard.publishEligible()).isFalse();
            assertThat(scorecard.activeRequirementsCount()).isEqualTo(0);
            assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(0);
            assertThat(scorecard.compliantCapabilitiesCount()).isEqualTo(0);

            // All 157 requirements must be partitioned into EXCLUDED_CAPABILITY or UNTESTED
            assertThat(scorecard.activeRequirementsCount() +
                    scorecard.excludedRequirementsCount() +
                    scorecard.untestedRequirementsCount())
                    .isEqualTo(157);

            // All 10 capabilities must be UNSUPPORTED with passRate = 0.0
            for (CapabilityStatus cap : scorecard.capabilities()) {
                assertThat(cap.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
                assertThat(cap.passRate()).isEqualTo(0.0);
                assertThat(cap.isSupported()).isFalse();
            }
        }

        @Test
        @DisplayName("When Core is ABORTED but an Optional Capability (filter) PASSES, active scope includes only filter")
        void testCoreAborted_OptionalCapabilityPassed() {
            ValidationRun run = createRun("PASSED");
            List<ValidationTestResult> testResults = new ArrayList<>();

            List<String> filterTestIds = catalogService.getTestsForCapability("filter");
            assertThat(filterTestIds).isNotEmpty();

            for (TestSpecMapping mapping : catalogService.getAllMappings()) {
                if (filterTestIds.contains(mapping.testId())) {
                    testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "SUCCESS"));
                } else {
                    testResults.add(createTestResult(mapping.testId(), mapping.displayName(), "ABORTED"));
                }
            }

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());

            // Active scope includes filter requirements and search requirements (exercised by composite tests FLT_17 and FLT_40)
            assertThat(scorecard.activeRequirementsCount()).isGreaterThan(0);
            assertThat(scorecard.coreScore()).isEqualTo(100);
            assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.EMERALD);
            // filter AND search are both supported due to composite tests FLT_17 and FLT_40
            assertThat(scorecard.supportedCapabilitiesCount()).isEqualTo(2);
            assertThat(scorecard.compliantCapabilitiesCount()).isEqualTo(2);

            Optional<CapabilityStatus> filterCap = scorecard.capabilities().stream()
                    .filter(c -> "filter".equals(c.capability())).findFirst();
            assertThat(filterCap).isPresent();
            assertThat(filterCap.get().status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
            assertThat(filterCap.get().passRate()).isEqualTo(100.0);

            Optional<CapabilityStatus> searchCap = scorecard.capabilities().stream()
                    .filter(c -> "search".equals(c.capability())).findFirst();
            assertThat(searchCap).isPresent();
            assertThat(searchCap.get().status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
        }

        @Test
        @DisplayName("Capability with all tests FAILED (executed > 0, passed = 0) is SUPPORTED_PARTIAL with passRate=0.0")
        void testCapabilityAllTestsFailed() {
            ValidationRun run = createRun("FAILED");
            List<ValidationTestResult> testResults = new ArrayList<>();

            List<String> sortTestIds = catalogService.getTestsForCapability("sort");
            assertThat(sortTestIds).isNotEmpty();

            for (String tid : sortTestIds) {
                testResults.add(createTestResult(tid, tid + ": Sorting test", "FAILED"));
            }

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, Collections.emptyList());

            Optional<CapabilityStatus> sortCap = scorecard.capabilities().stream()
                    .filter(c -> "sort".equals(c.capability())).findFirst();
            assertThat(sortCap).isPresent();
            assertThat(sortCap.get().status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_PARTIAL);
            assertThat(sortCap.get().passRate()).isEqualTo(0.0);
            assertThat(sortCap.get().isSupported()).isTrue();
            assertThat(sortCap.get().failedTests()).isEqualTo(sortTestIds.size());
            assertThat(sortCap.get().passedTests()).isEqualTo(0);
        }
    }

    // =========================================================================
    // 5. MATHEMATICAL ROUNDING PRECISION & PROPORTIONAL CREDIT ORACLES
    // =========================================================================
    @Nested
    @DisplayName("5. Mathematical Rounding Precision & Oracles")
    class MathematicalRoundingAndOracleTests {

        @Test
        @DisplayName("Math.round() at exact fractional boundaries (49.49 vs 49.50, 69.49 vs 69.50, 84.49 vs 84.50, 94.49 vs 94.50)")
        void testFractionalRoundingBoundaries() {
            SpecCatalogService mockCatalog = mock(SpecCatalogService.class);

            // Create 200 MUST requirements of weight 3 -> total weight = 600
            // Or simpler: 100 requirements of weight 1 -> total weight = 100
            // We can configure 2 requirements with weight 1 and weight 1 -> total weight = 200
            // Let's use 200 requirements each weight 1 (level=MAY):
            Map<String, SpecRequirement> reqMap = new LinkedHashMap<>();
            for (int i = 1; i <= 200; i++) {
                String id = "REQ-" + i;
                reqMap.put(id, new SpecRequirement(id, "7644", "3." + i, "Req " + i, "MAY", "none", "response", "tested", ""));
                when(mockCatalog.getTestsForRequirement(id)).thenReturn(List.of("T" + i));
            }
            when(mockCatalog.getRequirements()).thenReturn(reqMap);
            for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
            }

            ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
            ValidationRun run = createRun("PASSED");

            // 1. 99 out of 200 pass = 49.50% -> Math.round gives 50% -> ORANGE, publish eligible!
            List<ValidationTestResult> results49_5 = new ArrayList<>();
            for (int i = 1; i <= 200; i++) {
                results49_5.add(createTestResult("T" + i, "T" + i, i <= 99 ? "SUCCESS" : "FAILED"));
            }
            ComplianceScorecardView card50 = service.computeScorecard(run, results49_5, Collections.emptyList());
            assertThat(card50.coreScore()).isEqualTo(50);
            assertThat(card50.colourGradient()).isEqualTo(ColourGradient.ORANGE);
            assertThat(card50.publishEligible()).isTrue();

            // 2. 98 out of 200 pass = 49.00% -> Math.round gives 49% -> RED, publish ineligible!
            List<ValidationTestResult> results49_0 = new ArrayList<>();
            for (int i = 1; i <= 200; i++) {
                results49_0.add(createTestResult("T" + i, "T" + i, i <= 98 ? "SUCCESS" : "FAILED"));
            }
            ComplianceScorecardView card49 = service.computeScorecard(run, results49_0, Collections.emptyList());
            assertThat(card49.coreScore()).isEqualTo(49);
            assertThat(card49.colourGradient()).isEqualTo(ColourGradient.RED);
            assertThat(card49.publishEligible()).isFalse();

            // 3. 139 out of 200 pass = 69.50% -> rounds to 70% -> AMBER
            List<ValidationTestResult> results69_5 = new ArrayList<>();
            for (int i = 1; i <= 200; i++) {
                results69_5.add(createTestResult("T" + i, "T" + i, i <= 139 ? "SUCCESS" : "FAILED"));
            }
            ComplianceScorecardView card70 = service.computeScorecard(run, results69_5, Collections.emptyList());
            assertThat(card70.coreScore()).isEqualTo(70);
            assertThat(card70.colourGradient()).isEqualTo(ColourGradient.AMBER);

            // 4. 169 out of 200 pass = 84.50% -> rounds to 85% -> TEAL_GREEN
            List<ValidationTestResult> results84_5 = new ArrayList<>();
            for (int i = 1; i <= 200; i++) {
                results84_5.add(createTestResult("T" + i, "T" + i, i <= 169 ? "SUCCESS" : "FAILED"));
            }
            ComplianceScorecardView card85 = service.computeScorecard(run, results84_5, Collections.emptyList());
            assertThat(card85.coreScore()).isEqualTo(85);
            assertThat(card85.colourGradient()).isEqualTo(ColourGradient.TEAL_GREEN);

            // 5. 189 out of 200 pass = 94.50% -> rounds to 95% -> EMERALD
            List<ValidationTestResult> results94_5 = new ArrayList<>();
            for (int i = 1; i <= 200; i++) {
                results94_5.add(createTestResult("T" + i, "T" + i, i <= 189 ? "SUCCESS" : "FAILED"));
            }
            ComplianceScorecardView card95 = service.computeScorecard(run, results94_5, Collections.emptyList());
            assertThat(card95.coreScore()).isEqualTo(95);
            assertThat(card95.colourGradient()).isEqualTo(ColourGradient.EMERALD);
        }

        @Test
        @DisplayName("Proportional credit formula: multi-test requirement with mixed pass/fail/abort")
        void testProportionalCreditMultiTestMixedOutcomes() {
            SpecCatalogService mockCatalog = mock(SpecCatalogService.class);

            // REQ-MUST: weight 3, mapped to T1, T2, T3, T4.
            // Outcome: 2 SUCCESS, 1 FAILED, 1 ABORTED.
            // Executed tests = 3. Passed = 2.
            // Earned = 3 * (2 / 3) = 2.0.
            SpecRequirement reqMust = new SpecRequirement(
                    "REQ-MUST", "7644", "3.1", "Must Req", "MUST", "none", "response", "tested", "");

            // REQ-SHOULD: weight 2, mapped to T5, T6.
            // Outcome: 1 SUCCESS, 1 FAILED.
            // Executed tests = 2. Passed = 1.
            // Earned = 2 * (1 / 2) = 1.0.
            SpecRequirement reqShould = new SpecRequirement(
                    "REQ-SHOULD", "7644", "3.2", "Should Req", "SHOULD", "none", "response", "tested", "");

            when(mockCatalog.getRequirements()).thenReturn(Map.of("REQ-MUST", reqMust, "REQ-SHOULD", reqShould));
            when(mockCatalog.getTestsForRequirement("REQ-MUST")).thenReturn(List.of("T1", "T2", "T3", "T4"));
            when(mockCatalog.getTestsForRequirement("REQ-SHOULD")).thenReturn(List.of("T5", "T6"));
            for (String cap : ComplianceScoreService.OPTIONAL_CAPABILITIES) {
                when(mockCatalog.getTestsForCapability(cap)).thenReturn(Collections.emptyList());
            }

            ComplianceScoreService service = new ComplianceScoreService(mockCatalog);
            ValidationRun run = createRun("PASSED");

            List<ValidationTestResult> results = List.of(
                    createTestResult("T1", "T1", "SUCCESS"),
                    createTestResult("T2", "T2", "SUCCESS"),
                    createTestResult("T3", "T3", "FAILED"),
                    createTestResult("T4", "T4", "ABORTED"),
                    createTestResult("T5", "T5", "SUCCESS"),
                    createTestResult("T6", "T6", "FAILED")
            );

            ComplianceScorecardView scorecard = service.computeScorecard(run, results, Collections.emptyList());

            // Total earned = 2.0 + 1.0 = 3.0. Total weight = 3 + 2 = 5.0.
            // Score = round(100 * 3.0 / 5.0) = 60%.
            assertThat(scorecard.coreScore()).isEqualTo(60);
            assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.ORANGE);
            assertThat(scorecard.publishEligible()).isTrue();

            assertThat(scorecard.mustBreakdown().earnedPoints()).isEqualTo(2.0);
            assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(3.0);
            assertThat(scorecard.mustBreakdown().conformancePercent()).isEqualTo(67); // round(200 / 3) = 67%
            assertThat(scorecard.mustBreakdown().partialRequirements()).isEqualTo(1);

            assertThat(scorecard.shouldBreakdown().earnedPoints()).isEqualTo(1.0);
            assertThat(scorecard.shouldBreakdown().totalPoints()).isEqualTo(2.0);
            assertThat(scorecard.shouldBreakdown().conformancePercent()).isEqualTo(50);
            assertThat(scorecard.shouldBreakdown().partialRequirements()).isEqualTo(1);
        }
    }

    // =========================================================================
    // 6. CHANGEPASSWORD & DISCOVERY EDGE CASES
    // =========================================================================
    @Nested
    @DisplayName("6. ChangePassword & Exchange Parsing Robustness")
    class ChangePasswordDiscoveryTests {

        @Test
        @DisplayName("Malformed or non-200 exchanges fallback safely to UNSUPPORTED")
        void testChangePasswordExchangeFaultTolerance() {
            ValidationRun run = createRun("PASSED");

            // 1. Malformed JSON
            ValidationHttpExchange badJson = createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "{invalid json content");
            ComplianceScorecardView cardBadJson = scoreService.computeScorecard(run, Collections.emptyList(), List.of(badJson));
            CapabilityStatus capBad = getCap(cardBadJson, "changePassword");
            assertThat(capBad.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            assertThat(capBad.isSupported()).isFalse();

            // 2. HTTP 500 error response
            ValidationHttpExchange http500 = createExchange("https://scim.example.com/v2/ServiceProviderConfig", 500, "{\"changePassword\":{\"supported\":true}}");
            ComplianceScorecardView card500 = scoreService.computeScorecard(run, Collections.emptyList(), List.of(http500));
            CapabilityStatus cap500 = getCap(card500, "changePassword");
            assertThat(cap500.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);

            // 3. Different URL (not ServiceProviderConfig)
            ValidationHttpExchange wrongUrl = createExchange("https://scim.example.com/v2/Users", 200, "{\"changePassword\":{\"supported\":true}}");
            ComplianceScorecardView cardWrongUrl = scoreService.computeScorecard(run, Collections.emptyList(), List.of(wrongUrl));
            CapabilityStatus capWrong = getCap(cardWrongUrl, "changePassword");
            assertThat(capWrong.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);

            // 4. Empty body
            ValidationHttpExchange emptyBody = createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "   ");
            ComplianceScorecardView cardEmpty = scoreService.computeScorecard(run, Collections.emptyList(), List.of(emptyBody));
            CapabilityStatus capEmpty = getCap(cardEmpty, "changePassword");
            assertThat(capEmpty.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
        }

        private CapabilityStatus getCap(ComplianceScorecardView view, String cap) {
            return view.capabilities().stream()
                    .filter(c -> cap.equals(c.capability()))
                    .findFirst()
                    .orElseThrow();
        }
    }

    // =========================================================================
    // 7. TEST ID EXTRACTION ADVERSARIAL CASES
    // =========================================================================
    @Nested
    @DisplayName("7. Test ID Extraction Patterns")
    class TestIdExtractionTests {

        @ParameterizedTest(name = "Input=''{0}'' -> ExpectedId=''{1}''")
        @CsvSource({
                "'USER_01: Create User', 'USER_01'",
                "'RFC7643_02: Check Schema', 'RFC7643_02'",
                "'SCHEMA_03', 'SCHEMA_03'",
                "'  GRP_01: Add Member  ', 'GRP_01'",
                "'PAG_05: Cursor next', 'PAG_05'",
                "'DSC_01: ServiceProviderConfig', 'DSC_01'"
        })
        void testValidIdExtraction(String text, String expectedId) {
            assertThat(ComplianceScoreService.extractTestId(text)).isEqualTo(expectedId);
        }

        @ParameterizedTest(name = "Invalid input=''{0}'' -> null")
        @ValueSource(strings = {
                "no colon and spaces",
                "   ",
                "",
                "lower_case_id: test",
                "123-hyphen: test"
        })
        void testInvalidIdExtraction(String text) {
            assertThat(ComplianceScoreService.extractTestId(text)).isNull();
        }
    }

    // =========================================================================
    // 8. RANDOMIZED STRESS HARNESS (INVARIANTS VERIFICATION)
    // =========================================================================
    @Nested
    @DisplayName("8. Randomized Stress Harness across Catalog")
    class RandomizedStressHarnessTests {

        @Test
        @DisplayName("100 randomized executions satisfy all invariant mathematical properties")
        void testRandomizedRunsMaintainInvariants() {
            Random rng = new Random(42);
            List<TestSpecMapping> mappings = catalogService.getAllMappings();
            String[] statuses = {"SUCCESS", "FAILED", "ABORTED"};

            for (int iteration = 0; iteration < 100; iteration++) {
                String runStatus = rng.nextBoolean() ? "PASSED" : "FAILED";
                ValidationRun run = createRun(runStatus);

                List<ValidationTestResult> testResults = new ArrayList<>();
                for (TestSpecMapping mapping : mappings) {
                    // Assign random status with weighted distribution
                    String st = statuses[rng.nextInt(statuses.length)];
                    testResults.add(createTestResult(mapping.testId(), mapping.displayName(), st));
                }

                boolean cpSupported = rng.nextBoolean();
                ValidationHttpExchange cpExchange = createExchange(
                        "https://example.com/ServiceProviderConfig", 200,
                        "{\"changePassword\":{\"supported\":" + cpSupported + "}}"
                );

                ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(cpExchange));

                // Invariant 1: Score must be in [0, 100]
                assertThat(scorecard.coreScore()).isBetween(0, 100);

                // Invariant 2: ColourGradient must match score exactly
                assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.forScore(scorecard.coreScore()));

                // Invariant 3: Publish eligibility must match (terminal && score >= 50)
                boolean expectedEligible = ("PASSED".equals(runStatus) || "FAILED".equals(runStatus)) && scorecard.coreScore() >= 50;
                assertThat(scorecard.publishEligible()).isEqualTo(expectedEligible);

                // Invariant 4: Requirement partition consistency (active + excluded + untested == total catalog)
                int totalReqs = scorecard.activeRequirementsCount() +
                        scorecard.excludedRequirementsCount() +
                        scorecard.untestedRequirementsCount();
                assertThat(totalReqs).isEqualTo(157);

                // Invariant 5: Capabilities list size is always 10
                assertThat(scorecard.capabilities()).hasSize(10);

                // Invariant 6: Normative point bounds
                assertThat(scorecard.mustBreakdown().earnedPoints())
                        .isLessThanOrEqualTo(scorecard.mustBreakdown().totalPoints() + 0.0001);
                assertThat(scorecard.shouldBreakdown().earnedPoints())
                        .isLessThanOrEqualTo(scorecard.shouldBreakdown().totalPoints() + 0.0001);
                assertThat(scorecard.mayBreakdown().earnedPoints())
                        .isLessThanOrEqualTo(scorecard.mayBreakdown().totalPoints() + 0.0001);
            }
        }
    }

    private static ComplianceScorecardView createStubScorecard(int score, String status) {
        return new ComplianceScorecardView(
                UUID.randomUUID(), "Test", "http://example.com", OffsetDateTime.now(), status,
                score, ColourGradient.forScore(score),
                ("PASSED".equalsIgnoreCase(status) || "FAILED".equalsIgnoreCase(status)) && score >= 50,
                null, null, null, null,
                Collections.emptyList(), 0, 0, 10,
                157, 100, 0, 10,
                Collections.emptyMap(), Collections.emptyList()
        );
    }
}
