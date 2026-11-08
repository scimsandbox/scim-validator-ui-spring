package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.spec.RequirementTraceResult;
import de.palsoftware.scim.validator.ui.model.spec.SpecRequirement;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SpecCatalogServiceTest {

    private static SpecCatalogService service;

    @BeforeAll
    static void setUp() {
        service = new SpecCatalogService(new PathMatchingResourcePatternResolver());
        service.init();
    }

    @Test
    @DisplayName("Loads all 4 RFC catalogs with exactly 550 unique requirements")
    void testCatalogsLoaded_Exactly550Requirements() {
        Map<String, SpecRequirement> reqs = service.getRequirements();
        assertThat(reqs).hasSize(550);
        assertThat(service.getTotalRequirementsCount()).isEqualTo(550);
    }

    @Test
    @DisplayName("Requirement distribution across the 4 RFC catalogs matches canonical counts")
    void testRfcCatalogDistribution() {
        Map<String, SpecRequirement> reqs = service.getRequirements();

        long rfc7643Count = reqs.values().stream().filter(r -> "7643".equals(r.rfc())).count();
        long rfc7644Count = reqs.values().stream().filter(r -> "7644".equals(r.rfc())).count();
        long rfc9865Count = reqs.values().stream().filter(r -> "9865".equals(r.rfc())).count();
        long rfc9967Count = reqs.values().stream().filter(r -> "9967".equals(r.rfc())).count();

        assertThat(rfc7643Count).isEqualTo(195);
        assertThat(rfc7644Count).isEqualTo(275);
        assertThat(rfc9865Count).isEqualTo(31);
        assertThat(rfc9967Count).isEqualTo(49);
    }

    @Test
    @DisplayName("Normative RFC levels correctly assign MUST=3, SHOULD=2, MAY/OPTIONAL=1 weights")
    void testNormativeLevelDistributionAndWeights() {
        Map<String, SpecRequirement> reqs = service.getRequirements();

        long mustCount = reqs.values().stream().filter(SpecRequirement::isMust).count();
        long shouldCount = reqs.values().stream().filter(SpecRequirement::isShould).count();
        long mayOrOptCount = reqs.values().stream().filter(SpecRequirement::isMayOrOptional).count();

        assertThat(mustCount).isEqualTo(300);
        assertThat(shouldCount).isEqualTo(72);
        assertThat(mayOrOptCount).isEqualTo(178);

        int totalWeight = reqs.values().stream().mapToInt(SpecRequirement::getWeight).sum();
        assertThat(totalWeight).isEqualTo(300 * 3 + 72 * 2 + 178 * 1); // 900 + 144 + 178 = 1222
    }

    @Test
    @DisplayName("Level OPTIONAL is still weighted 1 by the weight function")
    void testOptionalLevelHandling() {
        SpecRequirement optReq = new SpecRequirement(
                "RFC9967-4-abcdef", "9967", "4", "", "OPTIONAL", "Sentence", "", "async", "unassigned");
        assertThat(optReq.getWeight()).isEqualTo(1);
        assertThat(optReq.isMayOrOptional()).isTrue();
    }

    @Test
    @DisplayName("Catalog fields from the generated YAML are exposed and title() returns the summary")
    void testGeneratedCatalogFieldsAndTitleAlias() {
        for (SpecRequirement req : service.getRequirements().values()) {
            assertThat(req.quote()).isNotBlank();
            assertThat(req.summary()).isNotBlank();
            assertThat(req.title()).isEqualTo(req.summary());
            assertThat(req.area()).isNotBlank();
        }

        SpecRequirement withSummary = new SpecRequirement(
                "RFC7643-4.2-36465a", "7643", "4.2", "displayName", "MUST", "REQUIRED.",
                "In the \"Group\" resource schema, the \"displayName\" attribute (a human-readable name for the Group) is REQUIRED.",
                "user-group-schemas", "core", "tested"
        );
        assertThat(withSummary.quote()).isEqualTo("REQUIRED.");
        assertThat(withSummary.summary()).contains("displayName");
        assertThat(withSummary.title()).isEqualTo(withSummary.summary());

        SpecRequirement fallbackToQuote = new SpecRequirement(
                "RFC7643-4.2-36465a", "7643", "4.2", "displayName", "MUST", "REQUIRED.",
                " ", "user-group-schemas", "core", "tested"
        );
        assertThat(fallbackToQuote.summary()).isEqualTo("REQUIRED.");
        assertThat(fallbackToQuote.title()).isEqualTo("REQUIRED.");
    }

    @Test
    @DisplayName("Blank capability means core and 'core' is the core capability")
    void testCoreCapabilityConvention() {
        SpecRequirement blank = new SpecRequirement("RFC7644-3-abcdef", "7644", "3", "", "MUST", "q", "", " ", "unassigned");
        SpecRequirement core = new SpecRequirement("RFC7644-3-abcdee", "7644", "3", "", "MUST", "q", "", "core", "unassigned");
        SpecRequirement patch = new SpecRequirement("RFC7644-3-abcded", "7644", "3", "", "MUST", "q", "", "patch", "unassigned");
        assertThat(blank.capability()).isEqualTo("core");
        assertThat(blank.isCore()).isTrue();
        assertThat(core.isCore()).isTrue();
        assertThat(patch.isCore()).isFalse();
        assertThat(patch.isOptionalCapability()).isTrue();
    }

    @Test
    @DisplayName("Dispositions: unassigned/gap/tested/blank are scored, optional/na are not")
    void testDispositionScoredFlag() {
        for (String disposition : new String[]{"unassigned", "gap", "tested", "", null}) {
            SpecRequirement req = new SpecRequirement("R-1", "7644", "3", "", "MUST", "q", "", "core", disposition);
            assertThat(req.isScored()).as("disposition %s", disposition).isTrue();
        }
        for (String disposition : new String[]{"optional", "na"}) {
            SpecRequirement req = new SpecRequirement("R-1", "7644", "3", "", "MUST", "q", "", "core", disposition);
            assertThat(req.isScored()).as("disposition %s", disposition).isFalse();
        }
    }

    @Test
    @DisplayName("Reflective inspection discovers the spock features, each tied to exactly one requirement")
    void testSpockReflection_DiscoversFeatures() {
        Map<String, TestSpecMapping> testMappings = service.getAllTestMappings();
        assertThat(testMappings).isNotEmpty();
        assertThat(service.getTotalTestsCount()).isEqualTo(testMappings.size());

        // Display name is "<requirement id>: <label>" and carries exactly one @SpecRef(<requirement id>)
        for (TestSpecMapping mapping : testMappings.values()) {
            assertThat(mapping.testId()).isNotBlank();
            assertThat(mapping.displayName()).startsWith(mapping.testId() + ":");
            assertThat(mapping.className()).isNotBlank();
            assertThat(mapping.specRefs()).containsExactly(mapping.testId());
            assertThat(service.getRequirement(mapping.testId())).isPresent();
        }
    }

    @Test
    @DisplayName("Capability index agrees with the capability of the requirement each test covers")
    void testCapabilityCoverageMapping() {
        for (TestSpecMapping mapping : service.getAllMappings()) {
            SpecRequirement req = service.getRequirement(mapping.testId()).orElseThrow();
            assertThat(mapping.requiredCapabilities()).containsExactly(req.capability());
            assertThat(service.getTestsForCapability(req.capability())).contains(mapping.testId());
        }
        // All non-core capabilities of the catalog are known to the UI
        Set<String> catalogCapabilities = service.getRequirements().values().stream()
                .map(SpecRequirement::capability).collect(Collectors.toSet());
        assertThat(catalogCapabilities).isSubsetOf(
                "core", "patch", "filter", "sort", "etag", "bulk", "search",
                "changePassword", "enterprise", "cursorPagination", "async");
    }

    @Test
    @DisplayName("Lookup resolves by short testId and full displayName")
    void testDualLookup_ByTestIdAndDisplayName() {
        TestSpecMapping first = service.getAllMappings().get(0);
        String id = first.testId();

        Optional<TestSpecMapping> byId = service.getTestMapping(id);
        assertThat(byId).contains(first);
        assertThat(byId.get().specRefs()).contains(id);

        assertThat(service.getTestMapping(first.displayName())).contains(first);

        List<TestSpecMapping> list = service.getMappingsForTest(id + ": any extra text");
        assertThat(list).isNotEmpty();
        assertThat(list.get(0).testId()).isEqualTo(id);

        // Test ids are requirement ids (letters, digits, '-' and '.'), shared pattern constant
        assertThat(ComplianceScoreService.TEST_ID_PATTERN).isSameAs(SpecCatalogService.TEST_ID_PATTERN);
        assertThat(id).matches(SpecCatalogService.RAW_TEST_ID_SYNTAX);
        assertThat(service.getTestMapping(id + ": sample description")).contains(first);
    }

    @Test
    @DisplayName("Every requirement id is a valid test id and display names are parsed to the id")
    void testRequirementIdsAreValidTestIds() {
        for (String id : service.getRequirements().keySet()) {
            assertThat(id).matches(SpecCatalogService.RAW_TEST_ID_SYNTAX);
            assertThat(ComplianceScoreService.extractTestId(id + ": some label")).isEqualTo(id);
            assertThat(ComplianceScoreService.extractTestId(id)).isEqualTo(id);
        }
        assertThat(ComplianceScoreService.extractTestId("RFC7643-2.3.6-1a2b3c: Label: with colon"))
                .isEqualTo("RFC7643-2.3.6-1a2b3c");
        assertThat(ComplianceScoreService.extractTestId("lowercase-start: x")).isNull();
        assertThat(ComplianceScoreService.extractTestId("Has Space: x")).isNull();
    }

    @Test
    @DisplayName("Spec class discovery fails clearly when the classpath scan finds nothing")
    void testDiscoveryFailsWithoutSpecClasses() throws Exception {
        ResourcePatternResolver empty = mock(ResourcePatternResolver.class);
        when(empty.getResources(anyString())).thenReturn(new Resource[0]);
        assertThatThrownBy(() -> SpecCatalogService.discoverValidatorSpecClassNames(empty))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No validator spec classes");
    }

    @Test
    @DisplayName("Spec class discovery finds the validator specs and excludes the base spec and inner classes")
    void testDiscoveryFindsSpecClasses() throws Exception {
        Set<String> classNames = SpecCatalogService.discoverValidatorSpecClassNames();
        assertThat(classNames).isNotEmpty();
        assertThat(classNames).isEqualTo(specClassesOnClasspath());
        assertThat(classNames).allMatch(n -> n.matches("de\\.palsoftware\\.scim\\.validator\\.specs\\.Rfc\\d{4}[A-Za-z]+Spec"));
        assertThat(classNames).allMatch(n -> n.startsWith("de.palsoftware.scim.validator.specs.Rfc") && n.endsWith("Spec"));
        assertThat(classNames).noneMatch(n -> n.contains("ScimBaseSpec") || n.contains("$"));
    }


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

    @Test
    @DisplayName("Every catalog requirement generates a valid RFC Editor section URL and label")
    void testRfcUrlGeneration() {
        for (SpecRequirement req : service.getRequirements().values()) {
            assertThat(req.rfcUrl())
                    .isEqualTo("https://www.rfc-editor.org/rfc/rfc" + req.rfc() + "#section-" + req.section());
            assertThat(req.rfcLabel())
                    .isEqualTo("RFC " + req.rfc() + " §" + req.section());
        }
    }

    @Test
    @DisplayName("rfcUrl() and rfcLabel() handle null and blank rfc or section safely")
    void testRfcUrlAndLabelBlankSectionAndRfcSafety() {
        // Blank or null section omits #section- and §
        SpecRequirement noSectionNull = new SpecRequirement(
                "REQ-1", "7644", null, "", "MUST", "Title", "", "core", "tested");
        assertThat(noSectionNull.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7644");
        assertThat(noSectionNull.rfcLabel()).isEqualTo("RFC 7644");

        SpecRequirement noSectionBlank = new SpecRequirement(
                "REQ-2", " 7643 ", "   ", "", "MUST", "Title", "", "core", "tested");
        assertThat(noSectionBlank.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7643");
        assertThat(noSectionBlank.rfcLabel()).isEqualTo("RFC 7643");

        RequirementTraceResult traceBlankSection = new RequirementTraceResult(
                "REQ-2", "7643", "", "Title", "MUST", 3, "core", true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("T1"));
        assertThat(traceBlankSection.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7643");
        assertThat(traceBlankSection.rfcLabel()).isEqualTo("RFC 7643");

        // Blank or null rfc returns null for rfcUrl() and empty string for rfcLabel()
        SpecRequirement noRfcNull = new SpecRequirement(
                "REQ-3", null, "4", "", "MUST", "Title", "", "core", "tested");
        assertThat(noRfcNull.rfcUrl()).isNull();
        assertThat(noRfcNull.rfcLabel()).isEmpty();

        SpecRequirement noRfcBlank = new SpecRequirement(
                "REQ-4", "   ", "4", "", "MUST", "Title", "", "core", "tested");
        assertThat(noRfcBlank.rfcUrl()).isNull();
        assertThat(noRfcBlank.rfcLabel()).isEmpty();

        RequirementTraceResult traceNullRfc = new RequirementTraceResult(
                "REQ-3", null, null, "Title", "MUST", 3, "core", false, 0, 0, 0, 0, 0, 0.0, "UNTESTED", List.of());
        assertThat(traceNullRfc.rfcUrl()).isNull();
        assertThat(traceNullRfc.rfcLabel()).isEmpty();
    }
}
