package de.palsoftware.scim.validator.ui.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
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
     * Resolves the authenticated OIDC user's canonical email ONLY when {@code email_verified} is
     * explicitly {@code true}. Mutable or unverified claims such as {@code preferred_username},
     * {@code upn}, and {@code unique_name} are never used as identity fallbacks.
     */
    public static String resolveEmail(OidcUser oidcUser) {
        if (oidcUser == null || !Boolean.TRUE.equals(oidcUser.getEmailVerified())) {
            return null;
        }
        return normalizeEmail(oidcUser.getEmail());
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
