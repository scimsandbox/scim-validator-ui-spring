package de.palsoftware.scim.validator.ui.model.spec;

import java.util.Collections;
import java.util.List;

public record TestSpecMapping(
        String testId,
        String displayName,
        String className,
        int lineNumber,
        String capability,
        List<String> requiredCapabilities,
        List<String> specRefs
) {
    public TestSpecMapping {
        if (requiredCapabilities == null) {
            requiredCapabilities = capability != null ? List.of(capability) : List.of("none");
        } else {
            requiredCapabilities = Collections.unmodifiableList(requiredCapabilities);
        }
        if (capability == null || capability.isBlank()) {
            capability = requiredCapabilities.isEmpty() ? "none" : requiredCapabilities.get(0);
        }
        if (specRefs == null) {
            specRefs = Collections.emptyList();
        } else {
            specRefs = Collections.unmodifiableList(specRefs);
        }
    }

    public TestSpecMapping(String testId, String displayName, String className, String capability, List<String> specRefs) {
        this(testId, displayName, className, 0, capability,
                capability != null ? List.of(capability) : List.of("none"), specRefs);
    }

    public TestSpecMapping(String testId, String displayName, String className, int lineNumber,
                           List<String> requiredCapabilities, List<String> specRefs) {
        this(testId, displayName, className, lineNumber,
                (requiredCapabilities != null && !requiredCapabilities.isEmpty()) ? requiredCapabilities.get(0) : "none",
                requiredCapabilities, specRefs);
    }

    public String testName() {
        return displayName;
    }
}
