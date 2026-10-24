package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.base.spec.RequiresCapability;
import de.palsoftware.scim.validator.base.spec.SpecRef;
import de.palsoftware.scim.validator.base.spec.SpecRefs;
import de.palsoftware.scim.validator.ui.model.spec.SpecRequirement;
import de.palsoftware.scim.validator.ui.model.spec.TestSpecMapping;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spockframework.runtime.model.FeatureMetadata;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SpecCatalogService {

    private static final Logger log = LoggerFactory.getLogger(SpecCatalogService.class);

    public static final List<String> CATALOG_RESOURCES = List.of(
            "classpath:spec/rfc7643-requirements.yaml",
            "classpath:spec/rfc7644-requirements.yaml",
            "classpath:spec/rfc9865-requirements.yaml",
            "classpath:spec/rfc9967-requirements.yaml"
    );

    public static final List<String> SPEC_CLASS_NAMES = List.of(
            "de.palsoftware.scim.validator.specs.A1_ServiceDiscoverySpec",
            "de.palsoftware.scim.validator.specs.A2_SchemaValidationSpec",
            "de.palsoftware.scim.validator.specs.A3_UserCrudSpec",
            "de.palsoftware.scim.validator.specs.A4_PatchOperationsSpec",
            "de.palsoftware.scim.validator.specs.A5_FilteringSpec",
            "de.palsoftware.scim.validator.specs.A5_PaginationSpec",
            "de.palsoftware.scim.validator.specs.A5_SortingSpec",
            "de.palsoftware.scim.validator.specs.A6_GroupLifecycleSpec",
            "de.palsoftware.scim.validator.specs.A7_BulkOperationsSpec",
            "de.palsoftware.scim.validator.specs.A8_SecurityAndRobustnessSpec",
            "de.palsoftware.scim.validator.specs.A9_NegativeAndEdgeCasesSpec",
            "de.palsoftware.scim.validator.specs.A10_CursorPaginationSpec",
            "de.palsoftware.scim.validator.specs.A11_AsyncOperationsSpec"
    );

    private static final Pattern TEST_ID_PATTERN = Pattern.compile("^([A-Z0-9_]+):\\s*(.*)");

    private final ResourcePatternResolver resourceResolver;
    private final Map<String, SpecRequirement> requirements = new LinkedHashMap<>();
    private final Map<String, TestSpecMapping> testMappingsById = new LinkedHashMap<>();
    private final Map<String, TestSpecMapping> testMappingsByDisplayName = new LinkedHashMap<>();
    private final Map<String, List<String>> requirementToTests = new LinkedHashMap<>();
    private final Map<String, List<String>> testsByCapability = new LinkedHashMap<>();
    private final List<TestSpecMapping> allMappings = new ArrayList<>();

    public SpecCatalogService(ResourcePatternResolver resourceResolver) {
        this.resourceResolver = resourceResolver;
    }

    @PostConstruct
    public void init() {
        loadCatalogs();
        scanSpockSpecifications();
        log.info("SpecCatalogService initialized with {} requirements and {} mapped tests across {} capabilities",
                requirements.size(), testMappingsById.size(), testsByCapability.size());
    }

    private void loadCatalogs() {
        Yaml yaml = new Yaml();
        for (String location : CATALOG_RESOURCES) {
            try (InputStream in = openResourceStream(location)) {
                List<Map<String, Object>> rows = yaml.load(in);
                if (rows != null) {
                    for (Map<String, Object> map : rows) {
                        String id = (String) map.get("id");
                        String rfc = map.get("rfc") != null ? String.valueOf(map.get("rfc")) : "";
                        String section = map.get("section") != null ? String.valueOf(map.get("section")) : "";
                        String title = (String) map.get("title");
                        String level = (String) map.get("level");
                        String capability = (String) map.get("capability");
                        String observability = (String) map.get("observability");
                        String disposition = (String) map.get("disposition");
                        String note = map.get("note") != null ? String.valueOf(map.get("note")) : "";

                        SpecRequirement req = new SpecRequirement(
                                id, rfc, section, title, level, capability, observability, disposition, note
                        );
                        requirements.put(req.id(), req);
                        requirementToTests.putIfAbsent(req.id(), new ArrayList<>());
                    }
                }
            } catch (Exception e) {
                log.error("Failed to load spec requirement catalog from {}", location, e);
                throw new IllegalStateException("Could not load catalog: " + location, e);
            }
        }
    }

    private InputStream openResourceStream(String location) throws IOException {
        if (resourceResolver != null) {
            Resource resource = resourceResolver.getResource(location);
            if (resource.exists()) {
                return resource.getInputStream();
            }
        }
        String cleanPath = location.replaceFirst("^classpath\\*?:/?", "");
        if (!cleanPath.startsWith("/")) {
            cleanPath = "/" + cleanPath;
        }
        InputStream in = getClass().getResourceAsStream(cleanPath);
        if (in == null) {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            if (cl != null) {
                in = cl.getResourceAsStream(cleanPath.substring(1));
            }
        }
        if (in == null) {
            in = ClassLoader.getSystemResourceAsStream(cleanPath.substring(1));
        }
        if (in == null) {
            throw new IOException("Cannot find catalog resource: " + location);
        }
        return in;
    }

    private void scanSpockSpecifications() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = getClass().getClassLoader();
        }

        for (String className : SPEC_CLASS_NAMES) {
            try {
                // CRITICAL: initialize = false prevents triggering ScimBaseSpec.<clinit>()
                Class<?> clazz = Class.forName(className, false, cl);
                RequiresCapability classCap = clazz.getAnnotation(RequiresCapability.class);
                String classCapValue = (classCap != null && !classCap.value().isBlank()) ? classCap.value().trim() : null;

                for (Method method : clazz.getDeclaredMethods()) {
                    FeatureMetadata feature = method.getAnnotation(FeatureMetadata.class);
                    if (feature == null) {
                        continue;
                    }

                    String displayName = feature.name();
                    Matcher matcher = TEST_ID_PATTERN.matcher(displayName);
                    String testId = matcher.find() ? matcher.group(1) : displayName;
                    int lineNumber = feature.line();

                    RequiresCapability methodCap = method.getAnnotation(RequiresCapability.class);
                    String methodCapValue = (methodCap != null && !methodCap.value().isBlank()) ? methodCap.value().trim() : null;

                    List<String> requiredCaps = new ArrayList<>();
                    if (classCapValue != null && !"none".equalsIgnoreCase(classCapValue)) {
                        requiredCaps.add(classCapValue);
                    }
                    if (methodCapValue != null && !"none".equalsIgnoreCase(methodCapValue) && !requiredCaps.contains(methodCapValue)) {
                        requiredCaps.add(methodCapValue);
                    }
                    if (requiredCaps.isEmpty()) {
                        requiredCaps.add("none");
                    }

                    String primaryCap = requiredCaps.get(0);

                    SpecRef[] refs = method.getAnnotationsByType(SpecRef.class);
                    if (refs == null || refs.length == 0) {
                        SpecRefs container = method.getAnnotation(SpecRefs.class);
                        if (container != null && container.value() != null) {
                            refs = container.value();
                        }
                    }

                    List<String> refIds = new ArrayList<>();
                    if (refs != null) {
                        for (SpecRef ref : refs) {
                            String refId = ref.value().trim();
                            refIds.add(refId);
                            requirementToTests.computeIfAbsent(refId, k -> new ArrayList<>()).add(testId);
                        }
                    }

                    TestSpecMapping mapping = new TestSpecMapping(
                            testId,
                            displayName,
                            className,
                            lineNumber,
                            requiredCaps,
                            refIds
                    );

                    testMappingsById.put(testId, mapping);
                    testMappingsByDisplayName.put(displayName, mapping);
                    allMappings.add(mapping);

                    for (String cap : requiredCaps) {
                        testsByCapability.computeIfAbsent(cap, k -> new ArrayList<>()).add(testId);
                    }
                }
            } catch (ClassNotFoundException e) {
                log.warn("Spock spec class not found on classpath: {}", className);
            }
        }
    }

    public Map<String, SpecRequirement> getRequirements() {
        return Collections.unmodifiableMap(requirements);
    }

    public Optional<SpecRequirement> getRequirement(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(requirements.get(id.trim()));
    }

    public Optional<TestSpecMapping> getTestMapping(String testId) {
        if (testId == null) return Optional.empty();
        String cleanId = testId.trim();
        TestSpecMapping direct = testMappingsById.get(cleanId);
        if (direct != null) return Optional.of(direct);

        Matcher m = TEST_ID_PATTERN.matcher(cleanId);
        if (m.find()) {
            TestSpecMapping byPrefix = testMappingsById.get(m.group(1));
            if (byPrefix != null) return Optional.of(byPrefix);
        }
        return Optional.ofNullable(testMappingsByDisplayName.get(cleanId));
    }

    public List<TestSpecMapping> getMappingsForTest(String testIdOrDisplayName) {
        Optional<TestSpecMapping> mapping = getTestMapping(testIdOrDisplayName);
        return mapping.map(List::of).orElse(Collections.emptyList());
    }

    public List<String> getTestsForRequirement(String reqId) {
        if (reqId == null) return Collections.emptyList();
        return Collections.unmodifiableList(requirementToTests.getOrDefault(reqId.trim(), Collections.emptyList()));
    }

    public List<String> getTestIdsForRequirement(String reqId) {
        return getTestsForRequirement(reqId);
    }

    public List<String> getTestsForCapability(String capability) {
        if (capability == null) return Collections.emptyList();
        return Collections.unmodifiableList(testsByCapability.getOrDefault(capability.trim(), Collections.emptyList()));
    }

    public Map<String, TestSpecMapping> getAllTestMappings() {
        return Collections.unmodifiableMap(testMappingsById);
    }

    public List<TestSpecMapping> getAllMappings() {
        return Collections.unmodifiableList(allMappings);
    }

    public int getTotalRequirementsCount() {
        return requirements.size();
    }

    public int getTotalTestsCount() {
        return testMappingsById.size();
    }
}
