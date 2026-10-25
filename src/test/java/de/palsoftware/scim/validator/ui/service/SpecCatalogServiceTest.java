package de.palsoftware.scim.validator.ui.service;

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
    @DisplayName("Loads all 4 RFC catalogs with exactly 157 unique requirements")
    void testCatalogsLoaded_Exactly157Requirements() {
        Map<String, SpecRequirement> reqs = service.getRequirements();
        assertThat(reqs).hasSize(157);
        assertThat(service.getTotalRequirementsCount()).isEqualTo(157);
    }

    @Test
    @DisplayName("Requirement distribution across the 4 RFC catalogs matches canonical counts")
    void testRfcCatalogDistribution() {
        Map<String, SpecRequirement> reqs = service.getRequirements();

        long rfc7643Count = reqs.values().stream().filter(r -> "7643".equals(r.rfc())).count();
        long rfc7644Count = reqs.values().stream().filter(r -> "7644".equals(r.rfc())).count();
        long rfc9865Count = reqs.values().stream().filter(r -> "9865".equals(r.rfc())).count();
        long rfc9967Count = reqs.values().stream().filter(r -> "9967".equals(r.rfc())).count();

        assertThat(rfc7643Count).isEqualTo(48);
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

        assertThat(mustCount).isEqualTo(134);
        assertThat(shouldCount).isEqualTo(9);
        assertThat(mayOrOptCount).isEqualTo(14); // 13 MAY + 1 OPTIONAL

        int totalWeight = reqs.values().stream().mapToInt(SpecRequirement::getWeight).sum();
        assertThat(totalWeight).isEqualTo(134 * 3 + 9 * 2 + 14 * 1); // 402 + 18 + 14 = 434
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
    @DisplayName("Reflective inspection of the 13 Spock specs discovers exactly 253 test methods")
    void testSpockReflection_Discovers253Tests() {
        Map<String, TestSpecMapping> testMappings = service.getAllTestMappings();
        assertThat(testMappings).hasSize(253);
        assertThat(service.getTotalTestsCount()).isEqualTo(253);

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
        assertThat(patchTests).hasSize(31);

        List<String> sortTests = service.getTestsForCapability("sort");
        assertThat(sortTests).hasSize(7);

        List<String> cursorTests = service.getTestsForCapability("cursorPagination");
        assertThat(cursorTests).hasSize(6);

        List<String> asyncTests = service.getTestsForCapability("async");
        assertThat(asyncTests).hasSize(3);

        List<String> enterpriseTests = service.getTestsForCapability("enterprise");
        assertThat(enterpriseTests).containsExactlyInAnyOrder("SCH_07", "USR_02", "USR_24");

        List<String> searchTests = service.getTestsForCapability("search");
        assertThat(searchTests).containsExactlyInAnyOrder("FLT_17", "FLT_40", "CUR_05");

        List<String> etagTests = service.getTestsForCapability("etag");
        assertThat(etagTests).hasSize(13);
        assertThat(etagTests).contains("USR_16", "PAT_20", "GRP_17", "GRP_19", "NEG_21");
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
}
