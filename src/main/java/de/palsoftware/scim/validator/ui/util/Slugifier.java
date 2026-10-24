package de.palsoftware.scim.validator.ui.util;

import java.util.Locale;

/**
 * Neutral utility for converting product names into URL-safe lowercase kebab-case slugs
 * in linear O(n) time without polynomial regular expressions.
 */
public final class Slugifier {

    private Slugifier() {
    }

    /**
     * Converts {@code input} to a lowercase kebab-case slug containing only {@code [a-z0-9-]}.
     */
    public static String slugify(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }
        String lower = input.trim().toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder(lower.length());
        boolean prevHyphen = false;
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                sb.append(c);
                prevHyphen = false;
            } else if (!sb.isEmpty() && !prevHyphen) {
                sb.append('-');
                prevHyphen = true;
            }
        }
        if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == '-') {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }
}
