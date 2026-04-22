package de.palsoftware.scim.validator.ui.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Locale;

public final class AuthenticatedUser {

    private AuthenticatedUser() {
    }

    public static String email(Authentication authentication) {
        if (authentication == null) {
            throw new IllegalStateException("Missing authentication");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            String resolved = resolveEmail(oidcUser);
            if (resolved != null) {
                return resolved;
            }
            throw new IllegalStateException("Authenticated principal is missing an email address");
        }
        String fallback = authentication.getName();
        if (fallback == null || fallback.isBlank()) {
            throw new IllegalStateException("Unable to resolve authenticated email");
        }
        return fallback;
    }

    public static String displayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        return email(authentication);
    }

    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public static String resolveEmail(OidcUser oidcUser) {
        if (oidcUser == null) {
            return null;
        }
        return normalizeEmail(firstNonBlank(
                oidcUser.getEmail(),
                oidcUser.getClaimAsString("upn"),
                oidcUser.getClaimAsString("unique_name"),
                oidcUser.getPreferredUsername()));
    }

    public static String normalizeEmail(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || !normalized.contains("@")) {
            return null;
        }
        return normalized;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
