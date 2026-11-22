package de.palsoftware.scim.validator.ui.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;

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
            throw new IllegalStateException("Authenticated principal is missing a verified email address");
        }
        String fallback = authentication.getName();
        if (fallback == null || fallback.isBlank()) {
            throw new IllegalStateException("Unable to resolve authenticated email");
        }
        String normalized = normalizeEmail(fallback);
        return normalized != null ? normalized : fallback;
    }

    public static String emailOrNull(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser) {
            return resolveEmail(oidcUser);
        }
        String fallback = authentication.getName();
        if (fallback == null || fallback.isBlank()) {
            return null;
        }
        String normalized = normalizeEmail(fallback);
        return normalized != null ? normalized : fallback;
    }

    public static String displayName(Authentication authentication) {
        return emailOrNull(authentication);
    }

    public static boolean isAdmin(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        if (authorities == null) {
            return false;
        }
        for (GrantedAuthority authority : authorities) {
            if (authority != null && "ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} only when the OIDC provider explicitly marks {@code email_verified} as
     * {@code false} (boolean {@code false} or case-insensitive string {@code "false"}). Enterprise,
     * SAML, and Entra ID connections frequently omit {@code email_verified} ({@code null}), whereas
     * self-signup database connections emit {@code "email_verified": false} until verified.
     */
    public static boolean isEmailExplicitlyUnverified(OidcUser oidcUser) {
        if (oidcUser == null) {
            return false;
        }
        if (Boolean.FALSE.equals(oidcUser.getEmailVerified())) {
            return true;
        }
        Map<String, Object> claims = oidcUser.getClaims();
        Object rawClaim = claims != null ? claims.get("email_verified") : null;
        if (rawClaim instanceof Boolean boolValue) {
            return !boolValue;
        }
        if (rawClaim instanceof String stringValue) {
            return "false".equalsIgnoreCase(stringValue.trim());
        }
        return false;
    }

    /**
     * Resolves the authenticated OIDC user's normalized email when {@code email_verified} is not
     * explicitly {@code false}, checking {@code email}, {@code upn}, {@code unique_name}, and
     * {@code preferred_username} in priority order.
     */
    public static String resolveEmail(OidcUser oidcUser) {
        if (oidcUser == null || isEmailExplicitlyUnverified(oidcUser)) {
            return null;
        }
        String[] candidates = {
                oidcUser.getEmail(),
                oidcUser.getClaimAsString("upn"),
                oidcUser.getClaimAsString("unique_name"),
                oidcUser.getPreferredUsername()
        };
        for (String candidate : candidates) {
            String normalized = normalizeEmail(candidate);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
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
}
