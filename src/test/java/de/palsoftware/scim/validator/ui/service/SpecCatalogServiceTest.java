package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.spec.RequirementTraceResult;
import de.palsoftware.scim.validator.ui.model.spec.SpecRequirement;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SpecCatalogServiceTest {

    private static SpecCatalogService service;

    @BeforeAll
    static void setUp() {
        service = new SpecCatalogService(new PathMatchingResourcePatternResolver());
        service.init();
    }

    @Test
    @DisplayName("Loads all 4 RFC catalogs with exactly 159 unique requirements")
    void testCatalogsLoaded_Exactly159Requirements() {
        Map<String, SpecRequirement> reqs = service.getRequirements();
        assertThat(reqs).hasSize(159);
        assertThat(service.getTotalRequirementsCount()).isEqualTo(159);
    }

    @Test
    @DisplayName("Requirement distribution across the 4 RFC catalogs matches canonical counts")
    void testRfcCatalogDistribution() {
        Map<String, SpecRequirement> reqs = service.getRequirements();

        // Note: rfc7643-requirements.yaml contains 49 entries and rfc7644-requirements.yaml contains 97 entries,
        // while the runtime rfc attribute distribution is 50 ("7643") and 96 ("7644") because RFC7644-4-R4 in
        // rfc7644-requirements.yaml declares rfc: "7643", section: "5" (referencing the ServiceProviderConfig
        // schema definition in RFC 7643 §5).
        long rfc7643Count = reqs.values().stream().filter(r -> "7643".equals(r.rfc())).count();
        long rfc7644Count = reqs.values().stream().filter(r -> "7644".equals(r.rfc())).count();
        long rfc9865Count = reqs.values().stream().filter(r -> "9865".equals(r.rfc())).count();
        long rfc9967Count = reqs.values().stream().filter(r -> "9967".equals(r.rfc())).count();

        assertThat(rfc7643Count).isEqualTo(50);
        assertThat(rfc7644Count).isEqualTo(96);
        assertThat(rfc9865Count).isEqualTo(8);
        assertThat(rfc9967Count).isEqualTo(5);
    }

    @Test
    @DisplayName("Normative RFC levels correctly assign MUST=3, SHOULD=2, MAY/OPTIONAL=1 weights")
    void testNormativeLevelDistributionAndWeights() {
        Map<String, SpecRequirement> reqs = service.getRequirements();

        long mustCount = reqs.values().stream().filter(SpecRequirement::isMust).count();
        long shouldCount = reqs.values().stream().filter(SpecRequirement::isShould).count();
        long mayOrOptCount = reqs.values().stream().filter(SpecRequirement::isMayOrOptional).count();

        assertThat(mustCount).isEqualTo(132);
        assertThat(shouldCount).isEqualTo(13);
        assertThat(mayOrOptCount).isEqualTo(14); // 13 MAY + 1 OPTIONAL

        int totalWeight = reqs.values().stream().mapToInt(SpecRequirement::getWeight).sum();
        assertThat(totalWeight).isEqualTo(132 * 3 + 13 * 2 + 14 * 1); // 396 + 26 + 14 = 436
    }

    @Test
    @DisplayName("RFC 9967 OPTIONAL requirement is recognized with weight 1")
    void testOptionalLevelHandling() {
        Optional<SpecRequirement> optReq = service.getRequirement("RFC9967-4-R1");
        assertThat(optReq).isPresent();
        assertThat(optReq.get().level()).isEqualTo("OPTIONAL");
        assertThat(optReq.get().getWeight()).isEqualTo(1);
        assertThat(optReq.get().isMayOrOptional()).isTrue();
    }

    @Test
    @DisplayName("Reflective inspection of the 13 Spock specs discovers exactly 274 test methods")
    void testSpockReflection_Discovers274Tests() {
        Map<String, TestSpecMapping> testMappings = service.getAllTestMappings();
        assertThat(testMappings).hasSize(274);
        assertThat(service.getTotalTestsCount()).isEqualTo(274);

        // Every test method must have a valid identifier, display name, class name, and >= 1 spec ref
        for (TestSpecMapping mapping : testMappings.values()) {
            assertThat(mapping.testId()).isNotBlank();
            assertThat(mapping.displayName()).isNotBlank();
            assertThat(mapping.className()).isNotBlank();
            assertThat(mapping.specRefs()).isNotEmpty();
        }
    }

    @Test
    @DisplayName("Discovers expected tests per capability (including composite tests)")
    void testCapabilityCoverageMapping() {
        List<String> bulkTests = service.getTestsForCapability("bulk");
        assertThat(bulkTests).hasSize(23);

        List<String> patchTests = service.getTestsForCapability("patch");
        assertThat(patchTests).hasSize(41);

        List<String> sortTests = service.getTestsForCapability("sort");
        assertThat(sortTests).hasSize(7);

        List<String> cursorTests = service.getTestsForCapability("cursorPagination");
        assertThat(cursorTests).hasSize(6);

        List<String> asyncTests = service.getTestsForCapability("async");
        assertThat(asyncTests).hasSize(3);

        List<String> enterpriseTests = service.getTestsForCapability("enterprise");
        assertThat(enterpriseTests).containsExactlyInAnyOrder("SCH_07", "USR_02", "USR_24", "PAT_10", "FLT_19", "FLT_34");

        List<String> searchTests = service.getTestsForCapability("search");
        assertThat(searchTests).containsExactlyInAnyOrder("FLT_16", "FLT_17", "FLT_33", "FLT_40", "PAG_07", "CUR_05");

        List<String> etagTests = service.getTestsForCapability("etag");
        assertThat(etagTests).hasSize(13);
        assertThat(etagTests).contains("USR_16", "PAT_20", "GRP_17", "GRP_19", "NEG_21");

        List<String> changePasswordTests = service.getTestsForCapability("changePassword");
        assertThat(changePasswordTests).containsExactlyInAnyOrder("USR_25", "PAT_32");

        Optional<TestSpecMapping> usr25Opt = service.getTestMapping("USR_25");
        assertThat(usr25Opt).isPresent();
        assertThat(usr25Opt.get().specRefs()).contains("RFC7643-4.1.1-R7");
        assertThat(usr25Opt.get().requiredCapabilities()).contains("changePassword");
    }

    @Test
    @DisplayName("Composite capability tests (e.g. PAT_20) appear in both capability indices")
    void testCompositeCapabilityTests() {
        Optional<TestSpecMapping> pat20 = service.getTestMapping("PAT_20");
        assertThat(pat20).isPresent();
        assertThat(pat20.get().requiredCapabilities()).contains("patch", "etag");

        assertThat(service.getTestsForCapability("patch")).contains("PAT_20");
        assertThat(service.getTestsForCapability("etag")).contains("PAT_20");
    }

    @Test
    @DisplayName("Lookup resolves by short testId and full displayName")
    void testDualLookup_ByTestIdAndDisplayName() {
        Optional<TestSpecMapping> byId = service.getTestMapping("DSC_01");
        assertThat(byId).isPresent();
        assertThat(byId.get().testId()).isEqualTo("DSC_01");
        assertThat(byId.get().specRefs()).contains("RFC7644-4-R1", "RFC7643-5-R1");

        Optional<TestSpecMapping> byFullName = service.getTestMapping(byId.get().displayName());
        assertThat(byFullName).isPresent();
        assertThat(byFullName.get()).isEqualTo(byId.get());

        List<TestSpecMapping> list = service.getMappingsForTest("DSC_01: any extra text");
        assertThat(list).isNotEmpty();
        assertThat(list.get(0).testId()).isEqualTo("DSC_01");
    }

    @Test
    @DisplayName("Untested catalog requirements exist with 0 mapped tests")
    void testUntestedRequirements() {
        // RFC7643-9.2-R1 (cleartext password storage in memory/storage) is non-observable and untestable via HTTP
        List<String> testsFor92R1 = service.getTestsForRequirement("RFC7643-9.2-R1");
        assertThat(testsFor92R1).isEmpty();

        // RFC7644-7.2-R1 (TLS enforcement) is untestable via HTTP
        List<String> testsFor72R1 = service.getTestsForRequirement("RFC7644-7.2-R1");
        assertThat(testsFor72R1).isEmpty();
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
                "REQ-1", "7644", null, "Title", "MUST", "none", "response", "tested", "");
        assertThat(noSectionNull.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7644");
        assertThat(noSectionNull.rfcLabel()).isEqualTo("RFC 7644");

        SpecRequirement noSectionBlank = new SpecRequirement(
                "REQ-2", " 7643 ", "   ", "Title", "MUST", "none", "response", "tested", "");
        assertThat(noSectionBlank.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7643");
        assertThat(noSectionBlank.rfcLabel()).isEqualTo("RFC 7643");

        RequirementTraceResult traceBlankSection = new RequirementTraceResult(
                "REQ-2", "7643", "", "Title", "MUST", 3, "none", true, 1, 1, 1, 0, 0, 3.0, "COMPLIANT", List.of("T1"));
        assertThat(traceBlankSection.rfcUrl()).isEqualTo("https://www.rfc-editor.org/rfc/rfc7643");
        assertThat(traceBlankSection.rfcLabel()).isEqualTo("RFC 7643");

        // Blank or null rfc returns null for rfcUrl() and empty string for rfcLabel()
        SpecRequirement noRfcNull = new SpecRequirement(
                "REQ-3", null, "4", "Title", "MUST", "none", "response", "tested", "");
        assertThat(noRfcNull.rfcUrl()).isNull();
        assertThat(noRfcNull.rfcLabel()).isEmpty();

        SpecRequirement noRfcBlank = new SpecRequirement(
                "REQ-4", "   ", "4", "Title", "MUST", "none", "response", "tested", "");
        assertThat(noRfcBlank.rfcUrl()).isNull();
        assertThat(noRfcBlank.rfcLabel()).isEmpty();

        RequirementTraceResult traceNullRfc = new RequirementTraceResult(
                "REQ-3", null, null, "Title", "MUST", 3, "none", false, 0, 0, 0, 0, 0, 0.0, "UNTESTED", List.of());
        assertThat(traceNullRfc.rfcUrl()).isNull();
        assertThat(traceNullRfc.rfcLabel()).isEmpty();
    }
}
