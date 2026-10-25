package de.palsoftware.scim.validator.ui.model.spec;

public record CapabilityStatus(
        String capability,
        String displayName,
        String rfcSection,
        CapabilitySupportLevel status,
        int totalTests,
        int executedTests,
        int passedTests,
        int failedTests,
        int abortedTests,
        double passRate,
        boolean isSupported
) {
    public static CapabilityStatus of(
            String capability,
            String displayName,
            String rfcSection,
            CapabilitySupportLevel status,
            int totalTests,
            int executedTests,
            int passedTests,
            int failedTests,
            int abortedTests) {
        double rate = executedTests > 0 ? (passedTests * 100.0) / executedTests : 0.0;
        boolean supported = status == CapabilitySupportLevel.SUPPORTED_COMPLIANT ||
                status == CapabilitySupportLevel.SUPPORTED_PARTIAL;
        return new CapabilityStatus(
                capability,
                displayName,
                rfcSection,
                status,
                totalTests,
                executedTests,
                passedTests,
                failedTests,
                abortedTests,
                rate,
                supported
        );
    }
}
