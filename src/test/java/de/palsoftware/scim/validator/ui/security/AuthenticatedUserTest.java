package de.palsoftware.scim.validator.ui.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticatedUserTest {

    @Test
    void email_nullAuthentication_throws() {
        assertThatThrownBy(() -> AuthenticatedUser.email(null))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Missing authentication");
    }

    @Test
    void email_nonOidcPrincipal_returnsAuthName() {
        Authentication auth = new TestingAuthenticationToken("john", "pass");

        String result = AuthenticatedUser.email(auth);

        assertThat(result).isEqualTo("john");
    }

    @ParameterizedTest
    @MethodSource("usernameOidcCases")
    void email_oidcClaims_returnExpectedEmail(Map<String, Object> claims, String expectedEmail) {
        OidcUser oidcUser = buildOidcUser(claims);
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        String result = AuthenticatedUser.email(auth);

        assertThat(result).isEqualTo(expectedEmail);
    }

    @Test
    void email_oidcPrincipal_returnsEmail() {
        OidcUser oidcUser = buildOidcUser(Map.of("sub", "oidc-sub-789", "email", "user@example.com"));
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        String result = AuthenticatedUser.email(auth);

        assertThat(result).isEqualTo("user@example.com");
    }

    @Test
    void displayName_nullAuthentication_returnsNull() {
        String result = AuthenticatedUser.displayName(null);

        assertThat(result).isNull();
    }

    @ParameterizedTest
    @MethodSource("displayNameOidcCases")
    void displayName_oidcClaims_returnExpectedDisplayName(Map<String, Object> claims, String expectedDisplayName) {
        OidcUser oidcUser = buildOidcUser(claims);
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        String result = AuthenticatedUser.displayName(auth);

        assertThat(result).isEqualTo(expectedDisplayName);
    }

    @Test
    void isAdmin_nullAuthentication_returnsFalse() {
        boolean result = AuthenticatedUser.isAdmin(null);

        assertThat(result).isFalse();
    }

    @Test
    void isAdmin_withRoleAdmin_returnsTrue() {
        Authentication auth = new TestingAuthenticationToken("user", "pass",
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        boolean result = AuthenticatedUser.isAdmin(auth);

        assertThat(result).isTrue();
    }

    @Test
    void isAdmin_withOtherRoles_returnsFalse() {
        Authentication auth = new TestingAuthenticationToken("user", "pass",
            List.of(new SimpleGrantedAuthority("ROLE_USER")));

        boolean result = AuthenticatedUser.isAdmin(auth);

        assertThat(result).isFalse();
    }

    @Test
    void isAdmin_noAuthorities_returnsFalse() {
        Authentication auth = new TestingAuthenticationToken("user", "pass");

        boolean result = AuthenticatedUser.isAdmin(auth);

        assertThat(result).isFalse();
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(3600);
        OidcIdToken idToken = new OidcIdToken("token-value", issuedAt, expiresAt, claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }

    private static Stream<Arguments> usernameOidcCases() {
        return Stream.of(
            Arguments.of(Map.of("sub", "sub-123", "preferred_username", "preferred.user@example.com"), "preferred.user@example.com"),
            Arguments.of(Map.of("sub", "sub-123", "upn", "user@contoso.com"), "user@contoso.com"),
            Arguments.of(Map.of("sub", "sub-123", "email", "user@example.com"), "user@example.com"),
            Arguments.of(Map.of("sub", "sub-456", "unique_name", "unique@example.com"), "unique@example.com")
        );
    }

    private static Stream<Arguments> displayNameOidcCases() {
        return Stream.of(
            Arguments.of(Map.of("sub", "sub-123", "email", "display@example.com"), "display@example.com"),
            Arguments.of(Map.of("sub", "sub-123", "preferred_username", "fallback.user@example.com"), "fallback.user@example.com")
        );
    }
}
