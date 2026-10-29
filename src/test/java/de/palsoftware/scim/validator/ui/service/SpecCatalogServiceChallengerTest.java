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
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

/**
 * Empirical Adversarial Challenger Test Suite for Milestone 2:
 * 1. SpecCatalogService reflection stability and classloading safety (verifying initialize=false prevents ScimBaseSpec crash).
 * 2. Catalog completeness invariants (159 requirements across 4 RFCs, normative levels & weights).
 * 3. Composite capabilities extraction and scoring (PAT_20, FLT_17, FLT_40, CUR_05).
 * 4. Safe handling of vintage runs without HTTP exchanges (zero NPEs).
 */
public class SpecCatalogServiceChallengerTest {

    private static SpecCatalogService service;
    private static ComplianceScoreService scoreService;
    private static PathMatchingResourcePatternResolver resolver;

    @BeforeAll
    static void setUp() {
        resolver = new PathMatchingResourcePatternResolver();
        service = new SpecCatalogService(resolver);
        service.init();
        scoreService = new ComplianceScoreService(service, new ObjectMapper());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. REFLECTION STABILITY & CLASSLOADING SAFETY INVARIANTS
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("1. Reflection Stability & Classloading Safety")
    class ReflectionStabilityTests {

        /**
         * Custom classloader that loads Spock specification classes freshly into isolation
         * without parent delegation, allowing empirical observation of <clinit> behavior.
         */
        static class IsolatedSpecClassLoader extends ClassLoader {
            private final ClassLoader parent;

            IsolatedSpecClassLoader(ClassLoader parent) {
                super(null); // No parent delegation for spec classes
                this.parent = parent;
            }

            @Override
            public Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.startsWith("de.palsoftware.scim.validator.specs.") ||
                    name.equals("de.palsoftware.scim.validator.base.ScimBaseSpec")) {
                    Class<?> alreadyLoaded = findLoadedClass(name);
                    if (alreadyLoaded != null) {
                        return alreadyLoaded;
                    }
                    String resourcePath = name.replace('.', '/') + ".class";
                    try (InputStream in = parent.getResourceAsStream(resourcePath)) {
                        if (in == null) {
                            throw new ClassNotFoundException("Resource not found: " + resourcePath);
                        }
                        byte[] bytes = in.readAllBytes();
                        Class<?> c = defineClass(name, bytes, 0, bytes.length);
                        if (resolve) {
                            resolveClass(c);
                        }
                        return c;
                    } catch (IOException e) {
                        throw new ClassNotFoundException("Failed to read class bytes for " + name, e);
                    }
                }
                return parent.loadClass(name);
            }
        }

        @Test
        @DisplayName("INVARIANT: Class.forName with initialize=true triggers ScimBaseSpec.<clinit>() crash when unconfigured")
        void testInitializeTrue_TriggersScimBaseSpecCrash() {
            IsolatedSpecClassLoader isolatedCl = new IsolatedSpecClassLoader(getClass().getClassLoader());
            String specClassName = "de.palsoftware.scim.validator.specs.A1_ServiceDiscoverySpec";

            // With initialize = true, JVM executes <clinit> which runs ScimBaseSpec.refreshConfiguration()
            // When SCIM_BASE_URL is unconfigured, refreshConfiguration() throws IllegalStateException
            assertThatThrownBy(() -> Class.forName(specClassName, true, isolatedCl))
                    .isInstanceOf(Throwable.class)
                    .satisfies(t -> {
                        boolean isInitError = t instanceof ExceptionInInitializerError;
                        boolean hasIllegalState = t.getCause() instanceof IllegalStateException ||
                                (t.getMessage() != null && t.getMessage().contains("SCIM"));
                        assertThat(isInitError || hasIllegalState)
                                .as("Expected initialization failure from ScimBaseSpec.<clinit>")
                                .isTrue();
                    });
        }

        @Test
        @DisplayName("INVARIANT: Class.forName with initialize=false safely introspects annotations without triggering <clinit>")
        void testInitializeFalse_LoadsSafelyWithoutCrash() throws Exception {
            IsolatedSpecClassLoader isolatedCl = new IsolatedSpecClassLoader(getClass().getClassLoader());
            String specClassName = "de.palsoftware.scim.validator.specs.A1_ServiceDiscoverySpec";

            // With initialize = false, bytecode is loaded without executing <clinit>
            Class<?> clazz = Class.forName(specClassName, false, isolatedCl);
            assertThat(clazz).isNotNull();
            assertThat(clazz.getName()).isEqualTo(specClassName);

            // Methods and annotations can be inspected without triggering class initialization
            Method[] methods = clazz.getDeclaredMethods();
            assertThat(methods).isNotEmpty();

            boolean foundFeatureMetadata = false;
            for (Method m : methods) {
                if (m.isAnnotationPresent(org.spockframework.runtime.model.FeatureMetadata.class)) {
                    foundFeatureMetadata = true;
                    org.spockframework.runtime.model.FeatureMetadata feature =
                            m.getAnnotation(org.spockframework.runtime.model.FeatureMetadata.class);
                    assertThat(feature.name()).isNotBlank();
                }
            }
            assertThat(foundFeatureMetadata).isTrue();
        }

        @Test
        @DisplayName("INVARIANT: All 13 Spock spec classes in SPEC_CLASS_NAMES can be safely loaded with initialize=false")
        void testAll13SpockSpecClassesLoadSafely() {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            assertThat(SpecCatalogService.SPEC_CLASS_NAMES).hasSize(13);

            for (String className : SpecCatalogService.SPEC_CLASS_NAMES) {
                assertThatCode(() -> {
                    Class<?> clazz = Class.forName(className, false, cl);
                    assertThat(clazz).isNotNull();
                }).doesNotThrowAnyException();
            }
        }

        @Test
        @DisplayName("INVARIANT: SpecCatalogService initializes cleanly in unconfigured environment")
        void testSpecCatalogServiceInit_UnconfiguredEnvironment() {
            SpecCatalogService fresh = new SpecCatalogService(resolver);
            assertThatCode(fresh::init).doesNotThrowAnyException();
            assertThat(fresh.getTotalRequirementsCount()).isEqualTo(159);
            assertThat(fresh.getTotalTestsCount()).isEqualTo(274);
        }

        @Test
        @DisplayName("INVARIANT: SpecCatalogService handles null or missing context ClassLoader gracefully")
        void testClassLoaderFallback_WhenContextClassLoaderIsNull() {
            ClassLoader originalCl = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(null);
                SpecCatalogService fallbackService = new SpecCatalogService(resolver);
                assertThatCode(fallbackService::init).doesNotThrowAnyException();
                assertThat(fallbackService.getTotalRequirementsCount()).isEqualTo(159);
                assertThat(fallbackService.getTotalTestsCount()).isEqualTo(274);
            } finally {
                Thread.currentThread().setContextClassLoader(originalCl);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. CATALOG COMPLETENESS & NORMATIVE INVARIANTS
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("2. Catalog Completeness & Normative Invariants")
    class CatalogCompletenessTests {

        @Test
        @DisplayName("INVARIANT: Raw YAML files contain exactly 159 unique requirement definitions (zero duplicate IDs)")
        void testRawYamlCountAndNoDuplicateIds() throws Exception {
            Yaml yaml = new Yaml();
            // Note: rfc7643-requirements.yaml has 49 entries and rfc7644-requirements.yaml has 97 entries,
            // while runtime rfc attribute distribution is 50 ("7643") and 96 ("7644") because RFC7644-4-R4 in
            // rfc7644-requirements.yaml declares rfc: "7643", section: "5" (referencing the ServiceProviderConfig
            // schema definition in RFC 7643 §5).
            Map<String, Integer> expectedFileCounts = Map.of(
                    "classpath:spec/rfc7643-requirements.yaml", 49,
                    "classpath:spec/rfc7644-requirements.yaml", 97,
                    "classpath:spec/rfc9865-requirements.yaml", 8,
                    "classpath:spec/rfc9967-requirements.yaml", 5
            );

            Set<String> seenIds = new HashSet<>();
            int totalParsed = 0;

            for (Map.Entry<String, Integer> entry : expectedFileCounts.entrySet()) {
                Resource resource = resolver.getResource(entry.getKey());
                assertThat(resource.exists()).as("Resource %s must exist", entry.getKey()).isTrue();

                try (InputStream in = resource.getInputStream()) {
                    List<Map<String, Object>> rows = yaml.load(in);
                    assertThat(rows).hasSize(entry.getValue());
                    for (Map<String, Object> map : rows) {
                        String id = (String) map.get("id");
                        assertThat(id).isNotBlank();
                        assertThat(seenIds.add(id))
                                .as("Requirement ID '%s' in %s must be globally unique across catalogs", id, entry.getKey())
                                .isTrue();
                        totalParsed++;
                    }
                }
            }

            assertThat(totalParsed).isEqualTo(159);
            assertThat(seenIds).hasSize(159);
        }

        @Test
        @DisplayName("INVARIANT: Normative levels strictly evaluate MUST=3, SHOULD=2, MAY/OPTIONAL=1 for total weight 436")
        void testNormativeWeightIntegrity() {
            Map<String, SpecRequirement> reqs = service.getRequirements();
            assertThat(reqs).hasSize(159);

            int mustCount = 0;
            int shouldCount = 0;
            int mayCount = 0;
            int optionalCount = 0;
            int totalPoints = 0;

            for (SpecRequirement r : reqs.values()) {
                String lvl = r.level();
                assertThat(lvl).isIn("MUST", "SHOULD", "MAY", "OPTIONAL");
                int w = r.getWeight();
                switch (lvl) {
                    case "MUST" -> {
                        assertThat(w).isEqualTo(3);
                        assertThat(r.isMust()).isTrue();
                        mustCount++;
                    }
                    case "SHOULD" -> {
                        assertThat(w).isEqualTo(2);
                        assertThat(r.isShould()).isTrue();
                        shouldCount++;
                    }
                    case "MAY" -> {
                        assertThat(w).isEqualTo(1);
                        assertThat(r.isMayOrOptional()).isTrue();
                        mayCount++;
                    }
                    case "OPTIONAL" -> {
                        assertThat(w).isEqualTo(1);
                        assertThat(r.isMayOrOptional()).isTrue();
                        optionalCount++;
                    }
                }
                totalPoints += w;
            }

            assertThat(mustCount).isEqualTo(132);
            assertThat(shouldCount).isEqualTo(13);
            assertThat(mayCount).isEqualTo(13);
            assertThat(optionalCount).isEqualTo(1);
            assertThat(totalPoints).isEqualTo(436);
        }

        @Test
        @DisplayName("INVARIANT: Every catalog requirement conforms to schema and valid capability vocabulary")
        void testRequirementSchemaConformity() {
            Set<String> validCapabilities = Set.of(
                    "none", "patch", "filter", "sort", "etag", "bulk", "search",
                    "changePassword", "enterprise", "cursorPagination", "async"
            );
            Set<String> validRfcs = Set.of("7643", "7644", "9865", "9967");
            Pattern idPattern = Pattern.compile("^RFC(7643|7644|9865|9967)-[0-9A-Za-z._-]+$");

            for (SpecRequirement req : service.getRequirements().values()) {
                assertThat(req.id()).matches(idPattern);
                assertThat(req.rfc()).isIn(validRfcs);
                assertThat(req.section()).isNotBlank();
                assertThat(req.title()).isNotBlank();
                assertThat(req.level()).isIn("MUST", "SHOULD", "MAY", "OPTIONAL");
                assertThat(req.capability()).isIn(validCapabilities);
                assertThat(req.observability()).isNotBlank();
                assertThat(req.disposition()).isNotBlank();
            }
        }

        @Test
        @DisplayName("INVARIANT: Exactly 2 catalog requirements are untested; all other 157 have >= 1 mapped test")
        void testUntestedVsTestedRequirements() {
            Map<String, SpecRequirement> reqs = service.getRequirements();
            List<String> untestedIds = new ArrayList<>();
            List<String> testedIds = new ArrayList<>();

            for (String reqId : reqs.keySet()) {
                List<String> tests = service.getTestsForRequirement(reqId);
                if (tests.isEmpty()) {
                    untestedIds.add(reqId);
                } else {
                    testedIds.add(reqId);
                }
            }

            assertThat(untestedIds).hasSize(2);
            assertThat(testedIds).hasSize(157);

            // Specifically verify non-observable requirements are in the untested set
            assertThat(untestedIds).contains(
                    "RFC7643-9.2-R1", // Password cleartext in storage
                    "RFC7644-7.2-R1"  // TLS requirement
            );
        }

        @Test
        @DisplayName("INVARIANT: Returned maps and lists from SpecCatalogService are immutable")
        void testReturnedCollectionsImmutability() {
            assertThatThrownBy(() -> service.getRequirements().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> service.getAllTestMappings().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> service.getAllMappings().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> service.getTestsForRequirement("RFC7644-4-R1").add("FAKE_TEST"))
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> service.getTestsForCapability("patch").add("FAKE_TEST"))
                    .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. SPOCK TEST DISCOVERY & TEST ID CONVENTIONS
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("3. Spock Test Discovery & Test ID Conventions")
    class SpockTestDiscoveryTests {

        @Test
        @DisplayName("INVARIANT: Discovers exactly 274 feature methods across 13 Spock specifications")
        void testExactly274FeatureMethods() {
            Map<String, TestSpecMapping> mappings = service.getAllTestMappings();
            assertThat(mappings).hasSize(274);
            assertThat(service.getAllMappings()).hasSize(274);

            // Verify test distribution across spec classes
            Map<String, Long> countByClass = mappings.values().stream()
                    .collect(Collectors.groupingBy(TestSpecMapping::className, Collectors.counting()));

            assertThat(countByClass).containsKeys(SpecCatalogService.SPEC_CLASS_NAMES.toArray(new String[0]));
            long totalFromClasses = countByClass.values().stream().mapToLong(Long::longValue).sum();
            assertThat(totalFromClasses).isEqualTo(274);
        }

        @Test
        @DisplayName("INVARIANT: Every mapped test conforms to ID syntax, class existence, and spec ref coverage")
        void testTestMappingInvariants() {
            Pattern idSyntax = Pattern.compile("^[A-Z0-9_]+$");

            for (TestSpecMapping mapping : service.getAllMappings()) {
                assertThat(mapping.testId()).matches(idSyntax);
                assertThat(mapping.displayName()).startsWith(mapping.testId() + ":");
                assertThat(mapping.className()).isIn(SpecCatalogService.SPEC_CLASS_NAMES);
                assertThat(mapping.lineNumber()).isGreaterThan(0);
                assertThat(mapping.requiredCapabilities()).isNotEmpty();
                assertThat(mapping.specRefs()).isNotEmpty();

                // Every specRef must exist in the 159 catalog requirements
                for (String refId : mapping.specRefs()) {
                    assertThat(service.getRequirement(refId))
                            .as("Test %s references requirement %s which must exist in catalog", mapping.testId(), refId)
                            .isPresent();
                }
            }
        }

        @Test
        @DisplayName("INVARIANT: Dual lookup by short ID, full display name, and prefixed string works robustly")
        void testDualLookupRobustness() {
            TestSpecMapping dsc01 = service.getTestMapping("DSC_01").orElseThrow();
            assertThat(dsc01.testId()).isEqualTo("DSC_01");

            assertThat(service.getTestMapping(dsc01.displayName())).contains(dsc01);
            assertThat(service.getTestMapping("DSC_01: extra custom suffix")).contains(dsc01);
            assertThat(service.getTestMapping("  DSC_01  ")).contains(dsc01);

            // Null, empty, unknown
            assertThat(service.getTestMapping(null)).isEmpty();
            assertThat(service.getTestMapping("")).isEmpty();
            assertThat(service.getTestMapping("NON_EXISTENT_TEST_999")).isEmpty();
            assertThat(service.getMappingsForTest(null)).isEmpty();
            assertThat(service.getTestsForRequirement(null)).isEmpty();
            assertThat(service.getTestsForCapability(null)).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. COMPOSITE CAPABILITIES (PAT_20, FLT_17, FLT_40, CUR_05)
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("4. Composite Capabilities")
    class CompositeCapabilityTests {

        @Test
        @DisplayName("INVARIANT: PAT_20 combines class-level patch and method-level etag capabilities")
        void testCompositeCapability_PAT_20() {
            TestSpecMapping pat20 = service.getTestMapping("PAT_20").orElseThrow();
            assertThat(pat20.className()).isEqualTo("de.palsoftware.scim.validator.specs.A4_PatchOperationsSpec");
            assertThat(pat20.requiredCapabilities()).containsExactly("patch", "etag");
            assertThat(pat20.specRefs()).contains("RFC7644-3.14-R1");

            // Appears in both capability test lists
            assertThat(service.getTestsForCapability("patch")).contains("PAT_20");
            assertThat(service.getTestsForCapability("etag")).contains("PAT_20");

            // Reverse lookup
            assertThat(service.getTestsForRequirement("RFC7644-3.14-R1")).contains("PAT_20");
        }

        @Test
        @DisplayName("INVARIANT: FLT_17 combines class-level filter and method-level search capabilities")
        void testCompositeCapability_FLT_17() {
            TestSpecMapping flt17 = service.getTestMapping("FLT_17").orElseThrow();
            assertThat(flt17.className()).isEqualTo("de.palsoftware.scim.validator.specs.A5_FilteringSpec");
            assertThat(flt17.requiredCapabilities()).containsExactly("filter", "search");
            assertThat(flt17.specRefs()).contains("RFC7644-3.4.3-R1");

            assertThat(service.getTestsForCapability("filter")).contains("FLT_17");
            assertThat(service.getTestsForCapability("search")).contains("FLT_17");
            assertThat(service.getTestsForRequirement("RFC7644-3.4.3-R1")).contains("FLT_17");
        }

        @Test
        @DisplayName("INVARIANT: FLT_40 combines class-level filter and method-level search capabilities")
        void testCompositeCapability_FLT_40() {
            TestSpecMapping flt40 = service.getTestMapping("FLT_40").orElseThrow();
            assertThat(flt40.className()).isEqualTo("de.palsoftware.scim.validator.specs.A5_FilteringSpec");
            assertThat(flt40.requiredCapabilities()).containsExactly("filter", "search");
            assertThat(flt40.specRefs()).contains("RFC7644-3.4.2.1-R1");

            assertThat(service.getTestsForCapability("filter")).contains("FLT_40");
            assertThat(service.getTestsForCapability("search")).contains("FLT_40");
            assertThat(service.getTestsForRequirement("RFC7644-3.4.2.1-R1")).contains("FLT_40");
        }

        @Test
        @DisplayName("INVARIANT: CUR_05 combines class-level cursorPagination and method-level search capabilities")
        void testCompositeCapability_CUR_05() {
            TestSpecMapping cur05 = service.getTestMapping("CUR_05").orElseThrow();
            assertThat(cur05.className()).isEqualTo("de.palsoftware.scim.validator.specs.A10_CursorPaginationSpec");
            assertThat(cur05.requiredCapabilities()).containsExactly("cursorPagination", "search");
            assertThat(cur05.specRefs()).contains("RFC9865-3-R1");

            assertThat(service.getTestsForCapability("cursorPagination")).contains("CUR_05");
            assertThat(service.getTestsForCapability("search")).contains("CUR_05");
            assertThat(service.getTestsForRequirement("RFC9865-3-R1")).contains("CUR_05");
        }

        @Test
        @DisplayName("INVARIANT: Scoring handles aborted composite tests without penalizing core score")
        void testCompositeCapabilityScoring_AbortedOptionalCapabilityExcludedFromDenominator() {
            ValidationRun run = new ValidationRun();
            run.setName("Composite Capability Stress Run");
            run.setStatus("PASSED");
            run.setExecutedAt(OffsetDateTime.now());

            List<ValidationTestResult> testResults = new ArrayList<>();
            // All tests succeed EXCEPT search and etag capability tests, which are ABORTED
            for (TestSpecMapping mapping : service.getAllMappings()) {
                ValidationTestResult tr = new ValidationTestResult();
                tr.setTestIdentifier(mapping.testId());
                tr.setDisplayName(mapping.displayName());
                tr.setTestName(mapping.displayName());

                if (mapping.requiredCapabilities().contains("etag") || mapping.requiredCapabilities().contains("search")) {
                    tr.setStatus("ABORTED");
                } else {
                    tr.setStatus("SUCCESS");
                }
                testResults.add(tr);
            }

            ValidationHttpExchange spcExchange = new ValidationHttpExchange();
            spcExchange.setUrl("https://example.com/scim/v2/ServiceProviderConfig");
            spcExchange.setResponseStatus(200);
            spcExchange.setResponseBody("{\"changePassword\":{\"supported\":true}}");

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(spcExchange));

            // Core score should remain 100% because unexecuted optional capability tests are excluded
            assertThat(scorecard.coreScore()).isEqualTo(100);
            assertThat(scorecard.colourGradient()).isEqualTo(ColourGradient.EMERALD);

            // etag and search capabilities must be UNSUPPORTED
            CapabilityStatus etagStatus = scorecard.capabilities().stream()
                    .filter(c -> "etag".equals(c.capability())).findFirst().orElseThrow();
            assertThat(etagStatus.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);

            CapabilityStatus searchStatus = scorecard.capabilities().stream()
                    .filter(c -> "search".equals(c.capability())).findFirst().orElseThrow();
            assertThat(searchStatus.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);

            // Requirements specific to search and etag must be EXCLUDED_CAPABILITY
            RequirementTraceResult traceFlt17 = scorecard.requirementMatrix().stream()
                    .filter(r -> "RFC7644-3.4.3-R1".equals(r.id())).findFirst().orElseThrow();
            assertThat(traceFlt17.status()).isEqualTo("EXCLUDED_CAPABILITY");
            assertThat(traceFlt17.inActiveScope()).isFalse();

            RequirementTraceResult tracePat20 = scorecard.requirementMatrix().stream()
                    .filter(r -> "RFC7644-3.14-R1".equals(r.id())).findFirst().orElseThrow();
            assertThat(tracePat20.status()).isEqualTo("EXCLUDED_CAPABILITY");
            assertThat(tracePat20.inActiveScope()).isFalse();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. VINTAGE RUNS & MISSING/MALFORMED HTTP EXCHANGES (NPE DEFENSE)
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("5. Vintage Runs & HTTP Exchanges Invariants")
    class VintageRunsAndExchangesTests {

        private ValidationRun createRun(String status) {
            ValidationRun run = new ValidationRun();
            run.setName("Vintage Run #100");
            run.setTargetUrl("https://scim.example.com/v2");
            run.setStatus(status);
            run.setExecutedAt(OffsetDateTime.now());
            return run;
        }

        @Test
        @DisplayName("INVARIANT: computeScorecard handles null exchanges list without NPE")
        void testVintageRun_NullExchanges_DoesNotThrowNpe() {
            ValidationRun run = createRun("PASSED");
            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run, Collections.emptyList(), null);
                assertThat(view).isNotNull();
                assertThat(view.coreScore()).isEqualTo(0);
                // changePassword defaults safely to UNSUPPORTED
                CapabilityStatus cp = view.capabilities().stream()
                        .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
                assertThat(cp.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("INVARIANT: computeScorecard handles empty exchanges list without NPE")
        void testVintageRun_EmptyExchanges_DoesNotThrowNpe() {
            ValidationRun run = createRun("PASSED");
            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run, Collections.emptyList(), Collections.emptyList());
                assertThat(view).isNotNull();
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("INVARIANT: computeScorecard single-argument overload handles empty run.getTestResults() without NPE")
        void testVintageRun_SingleArgOverload_DoesNotThrowNpe() {
            ValidationRun run = createRun("PASSED");
            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run);
                assertThat(view).isNotNull();
                assertThat(view.coreScore()).isEqualTo(0);
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("INVARIANT: computeScorecard with all null arguments returns safe default scorecard without NPE")
        void testAllNullArguments_ReturnsSafeDefault() {
            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(null, null, null);
                assertThat(view).isNotNull();
                assertThat(view.coreScore()).isEqualTo(0);
                assertThat(view.publishEligible()).isFalse();
                assertThat(view.runName()).isEqualTo("Validation Run");
                assertThat(view.targetUrl()).isEqualTo("");
                assertThat(view.runStatus()).isEqualTo("UNKNOWN");
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("INVARIANT: Corrupted and non-conforming HTTP exchanges are handled safely without NPE or crash")
        void testMalformedHttpExchangesHandledSafely() {
            ValidationRun run = createRun("PASSED");

            List<ValidationHttpExchange> malformedExchanges = List.of(
                    // Exchange with null URL
                    createExchange(null, 200, "{\"changePassword\":{\"supported\":true}}"),
                    // Exchange with non-matching URL
                    createExchange("https://scim.example.com/v2/Users", 200, "{\"changePassword\":{\"supported\":true}}"),
                    // Exchange with 500 status
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 500, "{\"changePassword\":{\"supported\":true}}"),
                    // Exchange with null response status
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", null, "{\"changePassword\":{\"supported\":true}}"),
                    // Exchange with null body
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, null),
                    // Exchange with blank body
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "   "),
                    // Exchange with unparseable HTML error body
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "<html><body>Gateway Timeout</body></html>"),
                    // Exchange with JSON array instead of object
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "[1, 2, 3]"),
                    // Exchange without changePassword field
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "{\"patch\":{\"supported\":true}}"),
                    // Exchange with non-boolean changePassword.supported
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "{\"changePassword\":{\"supported\":\"yes\"}}"),
                    // Exchange with null changePassword node
                    createExchange("https://scim.example.com/v2/ServiceProviderConfig", 200, "{\"changePassword\":null}")
            );

            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run, Collections.emptyList(), malformedExchanges);
                assertThat(view).isNotNull();
                CapabilityStatus cp = view.capabilities().stream()
                        .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
                // Should fall back safely to UNSUPPORTED
                assertThat(cp.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("INVARIANT: Valid changePassword discovery evaluates SUPPORTED_COMPLIANT vs UNSUPPORTED accurately")
        void testValidChangePasswordDiscovery() {
            ValidationRun run = createRun("PASSED");

            // True case
            ValidationHttpExchange exTrue = createExchange(
                    "https://scim.example.com/v2/ServiceProviderConfig", 200,
                    "{\"changePassword\":{\"supported\":true}}"
            );
            ComplianceScorecardView cardTrue = scoreService.computeScorecard(run, Collections.emptyList(), List.of(exTrue));
            CapabilityStatus cpTrue = cardTrue.capabilities().stream()
                    .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
            assertThat(cpTrue.status()).isEqualTo(CapabilitySupportLevel.SUPPORTED_COMPLIANT);
            assertThat(cpTrue.isSupported()).isTrue();

            // False case
            ValidationHttpExchange exFalse = createExchange(
                    "https://scim.example.com/v2/ServiceProviderConfig", 200,
                    "{\"changePassword\":{\"supported\":false}}"
            );
            ComplianceScorecardView cardFalse = scoreService.computeScorecard(run, Collections.emptyList(), List.of(exFalse));
            CapabilityStatus cpFalse = cardFalse.capabilities().stream()
                    .filter(c -> "changePassword".equals(c.capability())).findFirst().orElseThrow();
            assertThat(cpFalse.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            assertThat(cpFalse.isSupported()).isFalse();
        }

        @Test
        @DisplayName("INVARIANT: ValidationTestResult with null fields does not throw NPE during scoring")
        void testValidationTestResultWithNullFields_HandledSafely() {
            ValidationRun run = createRun("PASSED");

            ValidationTestResult trNullFields = new ValidationTestResult();
            trNullFields.setTestIdentifier(null);
            trNullFields.setDisplayName(null);
            trNullFields.setTestName(null);
            trNullFields.setStatus(null);

            ValidationTestResult trUnknownStatus = new ValidationTestResult();
            trUnknownStatus.setTestIdentifier("DSC_01");
            trUnknownStatus.setStatus("SOME_RANDOM_STATUS");

            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run, List.of(trNullFields, trUnknownStatus), Collections.emptyList());
                assertThat(view).isNotNull();
            }).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("EDGE CASE: Discovered vulnerability fixed - exchange list with null element handled gracefully without NPE")
        void testExchangeListWithNullElement_VulnerabilityFixed() {
            ValidationRun run = createRun("PASSED");
            List<ValidationHttpExchange> listWithNull = new ArrayList<>();
            listWithNull.add(null);
            assertThatCode(() -> {
                ComplianceScorecardView view = scoreService.computeScorecard(run, Collections.emptyList(), listWithNull);
                assertThat(view).isNotNull();
            }).doesNotThrowAnyException();
        }

        private ValidationHttpExchange createExchange(String url, Integer status, String body) {
            ValidationHttpExchange ex = new ValidationHttpExchange();
            ex.setUrl(url);
            ex.setResponseStatus(status);
            ex.setResponseBody(body);
            return ex;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 6. PHASE 1 TRACEABILITY & ADVERSARIAL INTEGRITY CHALLENGE
    // ─────────────────────────────────────────────────────────────────────────────
    @Nested
    @DisplayName("6. Phase 1 Traceability & Requirement Counts Challenge")
    class Phase1TraceabilityChallengeTests {

        @Test
        @DisplayName("CHALLENGE 1: Exactly 159 requirements and 274 Spock test methods mapped")
        void testRequirementAndTestCountsExact() {
            assertThat(service.getTotalRequirementsCount()).isEqualTo(159);
            assertThat(service.getRequirements()).hasSize(159);
            assertThat(service.getTotalTestsCount()).isEqualTo(274);
            assertThat(service.getAllTestMappings()).hasSize(274);
            assertThat(service.getAllMappings()).hasSize(274);
        }

        @Test
        @DisplayName("CHALLENGE 2: All 8 Phase 1 requirements have executable @SpecRef mappings and exact dispositions (tested for core, optional for capability-gated)")
        void testAll8Phase1RequirementsMapped() {
            Map<String, List<String>> expectedMappings = Map.of(
                    "RFC7643-2.2-R7", List.of("SCH_16"),
                    "RFC7643-2.3.7-R2", List.of("GRP_13", "GRP_15"),
                    "RFC7643-4.2-R3", List.of("GRP_16"),
                    "RFC7644-3.4.2.2-R15", List.of("FLT_44"),
                    "RFC7644-3.4.2.3-R4", List.of("SRT_06"),
                    "RFC7644-3.4.2.3-R5", List.of("SRT_07"),
                    "RFC7644-3.5.2-R4", List.of("PAT_01", "PAT_28"),
                    "RFC7644-3.5.2.1-R3", List.of("PAT_31")
            );
            Set<String> expectedCoreRequirements = Set.of(
                    "RFC7643-2.2-R7", "RFC7643-2.3.7-R2", "RFC7643-4.2-R3"
            );

            for (Map.Entry<String, List<String>> entry : expectedMappings.entrySet()) {
                String reqId = entry.getKey();
                List<String> expectedTestIds = entry.getValue();

                // Requirement exists in catalog; core requirements have disposition 'tested' and capability-gated requirements have 'optional'
                Optional<SpecRequirement> reqOpt = service.getRequirement(reqId);
                assertThat(reqOpt).as("Requirement %s must exist in catalog", reqId).isPresent();
                SpecRequirement req = reqOpt.get();
                assertThat(req.isCore()).isEqualTo(expectedCoreRequirements.contains(reqId));
                String expectedDisposition = req.isCore() ? "tested" : "optional";
                assertThat(req.disposition())
                        .as("Requirement %s (core=%s) disposition must be '%s'", reqId, req.isCore(), expectedDisposition)
                        .isEqualTo(expectedDisposition);

                // Mapped test list contains expected tests
                List<String> mappedTests = service.getTestsForRequirement(reqId);
                assertThat(mappedTests).as("Requirement %s must map to tests %s", reqId, expectedTestIds)
                        .containsAll(expectedTestIds);

                // Verify each test method mapping has valid @SpecRef and exists on target class
                for (String testId : expectedTestIds) {
                    Optional<TestSpecMapping> mappingOpt = service.getTestMapping(testId);
                    assertThat(mappingOpt).as("Test mapping for %s must exist", testId).isPresent();
                    TestSpecMapping mapping = mappingOpt.get();
                    assertThat(mapping.specRefs()).as("Test %s must declare @SpecRef(%s)", testId, reqId)
                            .contains(reqId);
                    assertThat(mapping.className()).isNotBlank();
                    assertThat(mapping.lineNumber()).isGreaterThan(0);
                }
            }
        }

        @Test
        @DisplayName("CHALLENGE 3: GRP_16 nested group test is properly discovered and mapped to RFC7643-4.2-R3")
        void testGRP16NestedGroupMappingIntegrity() {
            Optional<TestSpecMapping> grp16Opt = service.getTestMapping("GRP_16");
            assertThat(grp16Opt).as("GRP_16 must be discovered as a mapped test in SpecCatalogService").isPresent();

            TestSpecMapping grp16 = grp16Opt.get();
            assertThat(grp16.testId()).isEqualTo("GRP_16");
            assertThat(grp16.className()).isEqualTo("de.palsoftware.scim.validator.specs.A6_GroupLifecycleSpec");
            assertThat(grp16.displayName()).startsWith("GRP_16:");
            assertThat(grp16.specRefs()).containsExactly("RFC7643-4.2-R3");

            // Verify reverse lookup
            List<String> testsFor42R3 = service.getTestsForRequirement("RFC7643-4.2-R3");
            assertThat(testsFor42R3).contains("GRP_16");

            // Verify GRP_17 does NOT falsely claim RFC7643-4.2-R3 in runtime catalog
            Optional<TestSpecMapping> grp17Opt = service.getTestMapping("GRP_17");
            assertThat(grp17Opt).isPresent();
            assertThat(grp17Opt.get().specRefs()).doesNotContain("RFC7643-4.2-R3");
        }

        @Test
        @DisplayName("CHALLENGE 4: Untested requirements count is exactly 0 when all active tests pass")
        void testUntestedRequirementsCountZeroWhenAllPass() {
            ValidationRun run = new ValidationRun();
            run.setName("Phase 1 Full Pass Run");
            run.setStatus("PASSED");
            run.setExecutedAt(OffsetDateTime.now());

            List<ValidationTestResult> testResults = new ArrayList<>();
            for (TestSpecMapping mapping : service.getAllMappings()) {
                ValidationTestResult tr = new ValidationTestResult();
                tr.setTestIdentifier(mapping.testId());
                tr.setDisplayName(mapping.displayName());
                tr.setTestName(mapping.displayName());
                tr.setStatus("SUCCESS");
                testResults.add(tr);
            }

            ValidationHttpExchange spcExchange = new ValidationHttpExchange();
            spcExchange.setUrl("https://example.com/scim/v2/ServiceProviderConfig");
            spcExchange.setResponseStatus(200);
            spcExchange.setResponseBody("{\"changePassword\":{\"supported\":true}}");

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(spcExchange));

            assertThat(scorecard.coreScore()).isEqualTo(100);
            assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(159);
            assertThat(scorecard.activeRequirementsCount()).isEqualTo(157);
            assertThat(scorecard.untestedRequirementsCount()).isEqualTo(0);
            assertThat(scorecard.excludedRequirementsCount()).isEqualTo(2);

            // Verify that all 157 active requirements are COMPLIANT
            long compliantCount = scorecard.requirementMatrix().stream()
                    .filter(r -> "COMPLIANT".equals(r.status())).count();
            assertThat(compliantCount).isEqualTo(157);

            // Verify that 0 requirements in the matrix are UNTESTED
            long untestedMatrixCount = scorecard.requirementMatrix().stream()
                    .filter(r -> "UNTESTED".equals(r.status())).count();
            assertThat(untestedMatrixCount).isEqualTo(0);
        }

        @Test
        @DisplayName("CHALLENGE 5: Non-API-observable requirements (disposition: na) are excluded from Core Score denominator")
        void testDispositionNaGuaranteedExcludedFromCoreDenominator() {
            // RFC7643-9.2-R1 and RFC7644-7.2-R1 both have level: MUST (weight 3)
            SpecRequirement rfc7643_92r1 = service.getRequirement("RFC7643-9.2-R1").orElseThrow();
            SpecRequirement rfc7644_72r1 = service.getRequirement("RFC7644-7.2-R1").orElseThrow();

            assertThat(rfc7643_92r1.disposition()).isEqualTo("na");
            assertThat(rfc7644_72r1.disposition()).isEqualTo("na");
            assertThat(rfc7643_92r1.getWeight()).isEqualTo(3);
            assertThat(rfc7644_72r1.getWeight()).isEqualTo(3);

            // Total weight across all 159 catalog items: 436
            int totalCatalogWeight = service.getRequirements().values().stream()
                    .mapToInt(SpecRequirement::getWeight).sum();
            assertThat(totalCatalogWeight).isEqualTo(436);

            // With all active tests passing, denominator (mustTotal + shouldTotal + mayTotal)
            // must equal 436 - 3 - 3 = 430
            ValidationRun run = new ValidationRun();
            run.setName("Denominator Verification Run");
            run.setStatus("PASSED");
            run.setExecutedAt(OffsetDateTime.now());

            List<ValidationTestResult> testResults = new ArrayList<>();
            for (TestSpecMapping mapping : service.getAllMappings()) {
                ValidationTestResult tr = new ValidationTestResult();
                tr.setTestIdentifier(mapping.testId());
                tr.setDisplayName(mapping.displayName());
                tr.setTestName(mapping.displayName());
                tr.setStatus("SUCCESS");
                testResults.add(tr);
            }

            ValidationHttpExchange spcExchange = new ValidationHttpExchange();
            spcExchange.setUrl("https://example.com/scim/v2/ServiceProviderConfig");
            spcExchange.setResponseStatus(200);
            spcExchange.setResponseBody("{\"changePassword\":{\"supported\":true}}");

            ComplianceScorecardView scorecard = scoreService.computeScorecard(run, testResults, List.of(spcExchange));

            double activeDenominator = scorecard.mustBreakdown().totalPoints()
                    + scorecard.shouldBreakdown().totalPoints()
                    + scorecard.mayBreakdown().totalPoints();
            assertThat(activeDenominator).isEqualTo(430.0);
            assertThat(scorecard.mustBreakdown().totalPoints()).isEqualTo(130 * 3.0); // 132 - 2 na MUSTs = 130 MUSTs = 390.0

            // Adding an unmapped test result (DUMMY_NA_TEST) must not cause na requirements
            // (RFC7643-9.2-R1, RFC7644-7.2-R1) to be counted as active or untested
            ValidationTestResult dummyNaResult = new ValidationTestResult();
            dummyNaResult.setTestIdentifier("DUMMY_NA_TEST");
            dummyNaResult.setStatus("FAILED");
            List<ValidationTestResult> resultsWithDummy = new ArrayList<>(testResults);
            resultsWithDummy.add(dummyNaResult);

            ComplianceScorecardView scorecardWithDummy = scoreService.computeScorecard(run, resultsWithDummy, List.of(spcExchange));
            assertThat(scorecardWithDummy.untestedRequirementsCount()).isEqualTo(0);
            assertThat(scorecardWithDummy.excludedRequirementsCount()).isEqualTo(2);
            assertThat(scorecardWithDummy.coreScore()).isEqualTo(100);
        }
    }
}
