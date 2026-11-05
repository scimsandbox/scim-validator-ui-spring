package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.spec.SpecRequirement;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test catalog: the real generated catalogs and real spock mappings, restricted to the requirements that
 * have at least one mapped test. The generated catalogs list every normative sentence of the RFCs as
 * "unassigned", and unassigned requirements count against the score until a test covers them, so scoring
 * tests that expect a perfect run to reach 100 need the covered subset.
 */
final class CoveredSpecCatalog extends SpecCatalogService {

    private CoveredSpecCatalog() {
        super(new PathMatchingResourcePatternResolver());
    }

    static CoveredSpecCatalog create() {
        CoveredSpecCatalog catalog = new CoveredSpecCatalog();
        catalog.init();
        return catalog;
    }

    @Override
    public Map<String, SpecRequirement> getRequirements() {
        Map<String, SpecRequirement> covered = new LinkedHashMap<>();
        super.getRequirements().forEach((id, req) -> {
            if (!getTestsForRequirement(id).isEmpty()) {
                covered.put(id, req);
            }
        });
        return java.util.Collections.unmodifiableMap(covered);
    }

    @Override
    public int getTotalRequirementsCount() {
        return getRequirements().size();
    }
}
