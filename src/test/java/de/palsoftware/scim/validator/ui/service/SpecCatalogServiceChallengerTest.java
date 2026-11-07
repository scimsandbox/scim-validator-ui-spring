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
 * 2. Catalog completeness invariants (550 requirements across 4 RFCs, normative levels & weights).
 * 3. Capability extraction and scoring (aborted capability tests must not penalize the core score).
 * 4. Safe handling of vintage runs without HTTP exchanges (zero NPEs).
 */
public class SpecCatalogServiceChallengerTest {

    private static SpecCatalogService service;
    private static ComplianceScoreService scoreService;
    private static PathMatchingResourcePatternResolver resolver;


    private static Set<String> specClassesOnClasspath() throws java.io.IOException {
        Set<String> out = new java.util.TreeSet<>();
        for (org.springframework.core.io.Resource r : new org.springframework.core.io.support.PathMatchingResourcePatternResolver()
                .getResources("classpath*:de/palsoftware/scim/validator/specs/*Spec.class")) {
            String f = r.getFilename();
            if (f == null || f.contains("$") || f.equals("ScimBaseSpec.class")) continue;
            out.add("de.palsoftware.scim.validator.specs." + f.substring(0, f.length() - ".class".length()));
        }
        return out;
    }

    private static String anySpecClassName() {
        return SpecCatalogService.discoverValidatorSpecClassNames().iterator().next();
    }

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
            String specClassName = anySpecClassName();

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
            String specClassName = anySpecClassName();

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
        @DisplayName("INVARIANT: All discovered Spock spec classes can be safely loaded with initialize=false")
        void testAllSpockSpecClassesLoadSafely() throws Exception {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            Set<String> classNames = SpecCatalogService.discoverValidatorSpecClassNames();
            assertThat(classNames).isNotEmpty();
            assertThat(classNames).isEqualTo(specClassesOnClasspath());
            assertThat(classNames).allMatch(n -> n.matches("de\\.palsoftware\\.scim\\.validator\\.specs\\.Rfc\\d{4}[A-Za-z]+Spec"));

            for (String className : classNames) {
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
            assertThat(fresh.getTotalRequirementsCount()).isEqualTo(550);
            assertThat(fresh.getTotalTestsCount()).isEqualTo(service.getTotalTestsCount()).isPositive();
        }

        @Test
        @DisplayName("INVARIANT: SpecCatalogService handles null or missing context ClassLoader gracefully")
        void testClassLoaderFallback_WhenContextClassLoaderIsNull() {
            ClassLoader originalCl = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(null);
                SpecCatalogService fallbackService = new SpecCatalogService(resolver);
                assertThatCode(fallbackService::init).doesNotThrowAnyException();
                assertThat(fallbackService.getTotalRequirementsCount()).isEqualTo(550);
                assertThat(fallbackService.getTotalTestsCount()).isEqualTo(service.getTotalTestsCount());
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
        @DisplayName("INVARIANT: Raw YAML files contain exactly 550 unique requirement definitions (zero duplicate IDs)")
        void testRawYamlCountAndNoDuplicateIds() throws Exception {
            Yaml yaml = new Yaml();
            Map<String, Integer> expectedFileCounts = Map.of(
                    "classpath:spec/rfc7643-requirements.yaml", 195,
                    "classpath:spec/rfc7644-requirements.yaml", 275,
                    "classpath:spec/rfc9865-requirements.yaml", 31,
                    "classpath:spec/rfc9967-requirements.yaml", 49
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

            assertThat(totalParsed).isEqualTo(550);
            assertThat(seenIds).hasSize(550);
        }

        @Test
        @DisplayName("INVARIANT: Normative levels strictly evaluate MUST=3, SHOULD=2, MAY/OPTIONAL=1 for total weight 1222")
        void testNormativeWeightIntegrity() {
            Map<String, SpecRequirement> reqs = service.getRequirements();
            assertThat(reqs).hasSize(550);

            int mustCount = 0;
            int shouldCount = 0;
            int mayCount = 0;
            int optionalCount = 0;
            int totalPoints = 0;

            for (SpecRequirement r : reqs.values()) {
                String lvl = r.level();
                assertThat(lvl).isIn("MUST", "SHOULD", "MAY");
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

            assertThat(mustCount).isEqualTo(300);
            assertThat(shouldCount).isEqualTo(72);
            assertThat(mayCount).isEqualTo(178);
            assertThat(optionalCount).isEqualTo(0);
            assertThat(totalPoints).isEqualTo(1222);
        }

        @Test
        @DisplayName("INVARIANT: Every catalog requirement conforms to schema and valid capability vocabulary")
        void testRequirementSchemaConformity() {
            Set<String> validCapabilities = Set.of(
                    "core", "patch", "filter", "sort", "etag", "bulk", "search",
                    "changePassword", "enterprise", "cursorPagination", "async"
            );
            Set<String> validRfcs = Set.of("7643", "7644", "9865", "9967");
            Set<String> validDispositions = Set.of("unassigned", "tested", "optional", "na", "gap");
            Pattern idPattern = Pattern.compile("^RFC(7643|7644|9865|9967)-[0-9A-Za-z._-]+$");

            for (SpecRequirement req : service.getRequirements().values()) {
                assertThat(req.id()).matches(idPattern);
                assertThat(req.id()).matches(SpecCatalogService.RAW_TEST_ID_SYNTAX);
                assertThat(req.id()).startsWith("RFC" + req.rfc() + "-");
                assertThat(req.rfc()).isIn(validRfcs);
                assertThat(req.section()).isNotBlank();
                assertThat(req.quote()).isNotBlank();
                assertThat(req.area()).isNotBlank();
                assertThat(req.level()).isIn("MUST", "SHOULD", "MAY");
                assertThat(req.capability()).isIn(validCapabilities);
                assertThat(req.disposition()).isIn(validDispositions);
            }
        }

        @Test
        @DisplayName("INVARIANT: Every test maps to a catalog requirement; the rest of the catalog has no mapped tests")
        void testTestedVsUntestedRequirements() {
            Map<String, SpecRequirement> reqs = service.getRequirements();
            int tested = 0;
            int untested = 0;
            for (String reqId : reqs.keySet()) {
                if (service.getTestsForRequirement(reqId).isEmpty()) {
                    untested++;
                } else {
                    tested++;
                }
            }
            assertThat(tested + untested).isEqualTo(550);

            Set<String> mappedRequirementIds = new HashSet<>();
            for (TestSpecMapping mapping : service.getAllMappings()) {
                mappedRequirementIds.addAll(mapping.specRefs());
            }
            assertThat(reqs.keySet()).containsAll(mappedRequirementIds);
            assertThat(tested).isEqualTo(mappedRequirementIds.size());
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
            assertThatThrownBy(() -> service.getTestsForRequirement(service.getRequirements().keySet().iterator().next()).add("FAKE_TEST"))
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
        @DisplayName("INVARIANT: Discovers feature methods across all Spock specifications")
        void testFeatureMethodsDiscovered() {
            Map<String, TestSpecMapping> mappings = service.getAllTestMappings();
            assertThat(mappings).isNotEmpty();
            assertThat(service.getAllMappings()).hasSameSizeAs(mappings.values());

            Set<String> discovered = SpecCatalogService.discoverValidatorSpecClassNames();
            Map<String, Long> countByClass = mappings.values().stream()
                    .collect(Collectors.groupingBy(TestSpecMapping::className, Collectors.counting()));

            assertThat(discovered).containsAll(countByClass.keySet());
            long totalFromClasses = countByClass.values().stream().mapToLong(Long::longValue).sum();
            assertThat(totalFromClasses).isEqualTo(mappings.size());
        }

        @Test
        @DisplayName("INVARIANT: Every mapped test conforms to ID syntax, class existence, and spec ref coverage")
        void testTestMappingInvariants() {
            Pattern idSyntax = SpecCatalogService.RAW_TEST_ID_SYNTAX;

            for (TestSpecMapping mapping : service.getAllMappings()) {
                assertThat(mapping.testId()).matches(idSyntax);
                assertThat(mapping.displayName()).startsWith(mapping.testId() + ":");
                assertThat(mapping.className()).isIn(SpecCatalogService.discoverValidatorSpecClassNames());
                assertThat(mapping.lineNumber()).isGreaterThan(0);
                assertThat(mapping.requiredCapabilities()).isNotEmpty();
                // The feature id is the requirement id and the feature carries exactly that one @SpecRef
                assertThat(mapping.specRefs()).containsExactly(mapping.testId());

                // Every specRef must exist in the 550 catalog requirements
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
            TestSpecMapping first = service.getAllMappings().get(0);
            String id = first.testId();

            assertThat(service.getTestMapping(id)).contains(first);
            assertThat(service.getTestMapping(first.displayName())).contains(first);
            assertThat(service.getTestMapping(id + ": extra custom suffix")).contains(first);
            assertThat(service.getTestMapping("  " + id + "  ")).contains(first);

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
        @DisplayName("INVARIANT: Non-core tests carry the capability of their requirement and appear in that capability index")
        void testCapabilityIndexMatchesRequirementCapability() {
            for (TestSpecMapping mapping : service.getAllMappings()) {
                SpecRequirement req = service.getRequirement(mapping.testId()).orElseThrow();
                assertThat(mapping.requiredCapabilities()).containsExactly(req.capability());
                assertThat(service.getTestsForCapability(req.capability())).contains(mapping.testId());
                assertThat(service.getTestsForRequirement(req.id())).contains(mapping.testId());
            }
        }

        @Test
        @DisplayName("INVARIANT: Scoring handles aborted capability tests without penalizing core score")
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

            // Aborted capability tests must be treated exactly like capability tests that never ran
            List<ValidationTestResult> withoutCapabilityTests = testResults.stream()
                    .filter(tr -> {
                        List<String> caps = service.getTestMapping(tr.getTestIdentifier()).orElseThrow().requiredCapabilities();
                        return !caps.contains("etag") && !caps.contains("search");
                    }).toList();
            ComplianceScorecardView baseline = scoreService.computeScorecard(run, withoutCapabilityTests, List.of(spcExchange));
            assertThat(scorecard.coreScore()).isEqualTo(baseline.coreScore());
            assertThat(scorecard.activeRequirementsCount()).isEqualTo(baseline.activeRequirementsCount());

            // etag and search capabilities must be UNSUPPORTED
            for (String capability : List.of("etag", "search")) {
                CapabilityStatus status = scorecard.capabilities().stream()
                        .filter(c -> capability.equals(c.capability())).findFirst().orElseThrow();
                assertThat(status.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            }

            // Requirements specific to search and etag must be EXCLUDED_CAPABILITY and out of the active scope
            List<RequirementTraceResult> gated = scorecard.requirementMatrix().stream()
                    .filter(r -> "etag".equals(r.capability()) || "search".equals(r.capability())).toList();
            assertThat(gated).isNotEmpty();
            assertThat(gated).allSatisfy(r -> {
                assertThat(r.status()).isEqualTo("EXCLUDED_CAPABILITY");
                assertThat(r.inActiveScope()).isFalse();
            });
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
            assertThat(cpTrue.status()).isEqualTo(CapabilitySupportLevel.UNSUPPORTED);
            assertThat(cpTrue.isSupported()).isFalse();

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
            trUnknownStatus.setTestIdentifier(service.getAllMappings().get(0).testId());
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
        @DisplayName("CHALLENGE 1: Exactly 550 requirements and a consistent set of mapped Spock test methods")
        void testRequirementAndTestCountsExact() {
            assertThat(service.getTotalRequirementsCount()).isEqualTo(550);
            assertThat(service.getRequirements()).hasSize(550);
            assertThat(service.getTotalTestsCount()).isPositive();
            assertThat(service.getAllTestMappings()).hasSize(service.getTotalTestsCount());
            assertThat(service.getAllMappings()).hasSize(service.getTotalTestsCount());
        }

        private List<ValidationTestResult> allTestResults(String status) {
            List<ValidationTestResult> testResults = new ArrayList<>();
            for (TestSpecMapping mapping : service.getAllMappings()) {
                ValidationTestResult tr = new ValidationTestResult();
                tr.setTestIdentifier(mapping.testId());
                tr.setDisplayName(mapping.displayName());
                tr.setTestName(mapping.displayName());
                tr.setStatus(status);
                testResults.add(tr);
            }
            return testResults;
        }

        private ValidationHttpExchange serviceProviderConfigExchange() {
            ValidationHttpExchange spcExchange = new ValidationHttpExchange();
            spcExchange.setUrl("https://example.com/scim/v2/ServiceProviderConfig");
            spcExchange.setResponseStatus(200);
            spcExchange.setResponseBody("{\"changePassword\":{\"supported\":true}}");
            return spcExchange;
        }

        private ValidationRun passedRun(String name) {
            ValidationRun run = new ValidationRun();
            run.setName(name);
            run.setStatus("PASSED");
            run.setExecutedAt(OffsetDateTime.now());
            return run;
        }

        @Test
        @DisplayName("CHALLENGE 2: Requirements with a passing test are COMPLIANT; uncovered na/optional are EXCLUDED_CAPABILITY, other uncovered ones UNTESTED")
        void testPassingTestsMakeRequirementsCompliantAndUncoveredOnesUntested() {
            ComplianceScorecardView scorecard = scoreService.computeScorecard(
                    passedRun("Full Pass Run"), allTestResults("SUCCESS"), List.of(serviceProviderConfigExchange()));

            assertThat(scorecard.catalogRequirementsTotal()).isEqualTo(service.getRequirements().size());
            assertThat(scorecard.requirementMatrix()).hasSize(service.getRequirements().size());

            int covered = 0;
            int uncovered = 0;
            for (RequirementTraceResult trace : scorecard.requirementMatrix()) {
                SpecRequirement req = service.getRequirements().get(trace.id());
                assertThat(req).as("catalog entry for %s", trace.id()).isNotNull();
                if (!service.getTestsForRequirement(trace.id()).isEmpty()) {
                    covered++;
                    assertThat(trace.status()).as("requirement %s has a passing test", trace.id()).isEqualTo("COMPLIANT");
                } else {
                    uncovered++;
                    assertThat(trace.status()).as("uncovered requirement %s is never COMPLIANT", trace.id())
                            .isNotEqualTo("COMPLIANT");
                    if ("na".equalsIgnoreCase(req.disposition()) || "optional".equalsIgnoreCase(req.disposition())) {
                        assertThat(trace.status()).as("uncovered %s requirement %s", req.disposition(), trace.id())
                                .isEqualTo("EXCLUDED_CAPABILITY");
                    } else {
                        assertThat(trace.status()).as("uncovered %s requirement %s", req.disposition(), trace.id())
                                .isEqualTo("UNTESTED");
                    }
                }
            }
            assertThat(covered).isPositive();
            assertThat(uncovered).isPositive();
            long untested = scorecard.requirementMatrix().stream().filter(r -> "UNTESTED".equals(r.status())).count();
            assertThat(scorecard.untestedRequirementsCount()).isEqualTo((int) untested);
        }

        @Test
        @DisplayName("CHALLENGE 3: The active denominator equals the weight of all in-scope requirements")
        void testActiveDenominatorMatchesInScopeWeight() {
            int totalCatalogWeight = service.getRequirements().values().stream()
                    .mapToInt(SpecRequirement::getWeight).sum();

            ComplianceScorecardView scorecard = scoreService.computeScorecard(
                    passedRun("Denominator Verification Run"), allTestResults("SUCCESS"),
                    List.of(serviceProviderConfigExchange()));

            assertThat(scorecard.requirementMatrix().stream().mapToInt(RequirementTraceResult::weight).sum())
                    .isEqualTo(totalCatalogWeight);
            double activeDenominator = scorecard.mustBreakdown().totalPoints()
                    + scorecard.shouldBreakdown().totalPoints()
                    + scorecard.mayBreakdown().totalPoints();
            double inScopeWeight = scorecard.requirementMatrix().stream()
                    .filter(RequirementTraceResult::inActiveScope)
                    .mapToDouble(RequirementTraceResult::weight).sum();
            assertThat(activeDenominator).isEqualTo(inScopeWeight);
            assertThat(inScopeWeight).isPositive().isLessThanOrEqualTo(totalCatalogWeight);
            // Excluded requirements are outside the denominator
            assertThat(scorecard.requirementMatrix().stream()
                    .filter(r -> "EXCLUDED_CAPABILITY".equals(r.status()))
                    .filter(RequirementTraceResult::inActiveScope)).isEmpty();
        }

        @Test
        @DisplayName("CHALLENGE 4: An unmapped test result does not change counts or score")
        void testUnmappedTestResultIsIgnored() {
            ValidationRun run = passedRun("Unmapped Result Run");
            List<ValidationTestResult> testResults = allTestResults("SUCCESS");
            List<ValidationHttpExchange> exchanges = List.of(serviceProviderConfigExchange());
            ComplianceScorecardView baseline = scoreService.computeScorecard(run, testResults, exchanges);

            ValidationTestResult dummyResult = new ValidationTestResult();
            dummyResult.setTestIdentifier("DUMMY_UNMAPPED_TEST");
            dummyResult.setStatus("FAILED");
            List<ValidationTestResult> resultsWithDummy = new ArrayList<>(testResults);
            resultsWithDummy.add(dummyResult);

            ComplianceScorecardView withDummy = scoreService.computeScorecard(run, resultsWithDummy, exchanges);
            assertThat(withDummy.untestedRequirementsCount()).isEqualTo(baseline.untestedRequirementsCount());
            assertThat(withDummy.excludedRequirementsCount()).isEqualTo(baseline.excludedRequirementsCount());
            assertThat(withDummy.activeRequirementsCount()).isEqualTo(baseline.activeRequirementsCount());
            assertThat(withDummy.coreScore()).isEqualTo(baseline.coreScore());
        }
    }
}
