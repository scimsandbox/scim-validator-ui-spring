package de.palsoftware.scim.validator.ui.util;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Validates and normalizes required base-URL configuration. The value is used as a link target and is
 * concatenated with fixed paths ({@code base + "/news/index.json"}), so it must be an absolute
 * http(s) URL with a host and must not end in a slash.
 */
public final class BaseUrl {

    private BaseUrl() {
    }

    /**
     * Trims {@code value} and strips trailing slashes.
     *
     * @param property the property key, only used for the error message
     * @throws IllegalStateException if the value is missing, blank, or not an absolute http(s) URL with a host
     */
    public static String require(String property, String value) {
        String normalized = value == null ? "" : value.trim();
        int end = normalized.length();
        while (end > 0 && normalized.charAt(end - 1) == '/') {
            end--;
        }
        normalized = normalized.substring(0, end);
        try {
            URI uri = new URI(normalized);
            String scheme = uri.getScheme();
            boolean http = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
            if (http && uri.getHost() != null) {
                return normalized;
            }
        } catch (URISyntaxException ex) {
            // fall through to the descriptive error below
        }
        throw new IllegalStateException(property + " must be an absolute http(s) URL, e.g. https://scimsandbox.net");
    }
}
