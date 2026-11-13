package de.palsoftware.scim.validator.ui.util;

/**
 * Normalizes required base-URL configuration, which is concatenated with fixed paths
 * ({@code base + "/news/index.json"}), so trailing slashes must not survive.
 */
public final class BaseUrl {

    private BaseUrl() {
    }

    /**
     * Trims {@code value} and strips trailing slashes.
     *
     * @param property the property key, only used for the error message
     * @throws IllegalStateException if the value is missing or blank
     */
    public static String require(String property, String value) {
        String normalized = value == null ? "" : value.trim();
        int end = normalized.length();
        while (end > 0 && normalized.charAt(end - 1) == '/') {
            end--;
        }
        normalized = normalized.substring(0, end);
        if (normalized.isEmpty()) {
            throw new IllegalStateException(property + " must be set to a base URL");
        }
        return normalized;
    }
}
