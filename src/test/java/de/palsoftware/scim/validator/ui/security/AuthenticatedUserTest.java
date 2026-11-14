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
    void emailOrNull_nullAuthentication_returnsNull() {
        assertThat(AuthenticatedUser.emailOrNull(null)).isNull();
    }

    @Test
    void email_nonOidcPrincipal_returnsNormalizedAuthName() {
        Authentication auth = new TestingAuthenticationToken("  John.Doe@Example.com  ", "pass");

        String result = AuthenticatedUser.email(auth);

        assertThat(result).isEqualTo("john.doe@example.com");
    }

    @Test
    void email_oidcPrincipalWithVerifiedEmail_emailWinsOverPreferredUsername() {
        OidcUser oidcUser = buildOidcUser(Map.of(
                "sub", "oidc-sub-789",
                "email", "  User@Example.COM ",
                "email_verified", true,
                "preferred_username", "spoofed@victim.com"
        ));
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(oidcUser)).isFalse();
        assertThat(AuthenticatedUser.email(auth)).isEqualTo("user@example.com");
        assertThat(AuthenticatedUser.emailOrNull(auth)).isEqualTo("user@example.com");
    }

    @ParameterizedTest
    @MethodSource("allowedEnterpriseAndFallbackOidcCases")
    void email_oidcEnterpriseOmittedEmailVerifiedAndClaimFallbacks_resolveInPriorityOrder(
            Map<String, Object> claims,
            String expectedEmail) {
        OidcUser oidcUser = buildOidcUser(claims);
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(oidcUser)).isFalse();
        assertThat(AuthenticatedUser.email(auth)).isEqualTo(expectedEmail);
        assertThat(AuthenticatedUser.emailOrNull(auth)).isEqualTo(expectedEmail);
    }

    @ParameterizedTest
    @MethodSource("explicitlyUnverifiedOrMissingEmailOidcCases")
    void email_oidcExplicitlyUnverifiedOrNoValidEmailClaims_rejects(
            Map<String, Object> claims,
            boolean expectedExplicitlyUnverified) {
        OidcUser oidcUser = buildOidcUser(claims);
        Authentication auth = new TestingAuthenticationToken(oidcUser, "n/a");

        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(oidcUser)).isEqualTo(expectedExplicitlyUnverified);
        assertThatThrownBy(() -> AuthenticatedUser.email(auth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("verified email");
        assertThat(AuthenticatedUser.emailOrNull(auth)).isNull();
    }

    @Test
    void displayName_nullAuthentication_returnsNull() {
        assertThat(AuthenticatedUser.displayName(null)).isNull();
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
        assertThat(AuthenticatedUser.isAdmin(null)).isFalse();
    }

    @Test
    void isAdmin_withRoleAdmin_returnsTrue() {
        Authentication auth = new TestingAuthenticationToken("user", "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        assertThat(AuthenticatedUser.isAdmin(auth)).isTrue();
    }

    @Test
    void isAdmin_withOtherRoles_returnsFalse() {
        Authentication auth = new TestingAuthenticationToken("user", "pass",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(AuthenticatedUser.isAdmin(auth)).isFalse();
    }

    @Test
    void isAdmin_noAuthorities_returnsFalse() {
        Authentication auth = new TestingAuthenticationToken("user", "pass");

        assertThat(AuthenticatedUser.isAdmin(auth)).isFalse();
    }

    @Test
    void emailAndEmailOrNull_nonOidcBlankAndNonEmailPrincipals_handleAllBranches() {
        Authentication blankAuth = new TestingAuthenticationToken("   ", "pass");
        assertThatThrownBy(() -> AuthenticatedUser.email(blankAuth))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unable to resolve");
        assertThat(AuthenticatedUser.emailOrNull(blankAuth)).isNull();

        Authentication plainUsernameAuth = new TestingAuthenticationToken("service-account", "pass");
        assertThat(AuthenticatedUser.email(plainUsernameAuth)).isEqualTo("service-account");
        assertThat(AuthenticatedUser.emailOrNull(plainUsernameAuth)).isEqualTo("service-account");
    }

    @Test
    void isAdmin_nullAuthoritiesCollectionOrNullAuthorityElement_returnsFalse() {
        Authentication nullAuthoritiesAuth = org.mockito.Mockito.mock(Authentication.class);
        org.mockito.Mockito.when(nullAuthoritiesAuth.getAuthorities()).thenReturn(null);
        assertThat(AuthenticatedUser.isAdmin(nullAuthoritiesAuth)).isFalse();

        List<org.springframework.security.core.GrantedAuthority> withNull = new java.util.ArrayList<>();
        withNull.add(null);
        withNull.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        Authentication mixedAuthoritiesAuth = org.mockito.Mockito.mock(Authentication.class);
        org.mockito.Mockito.doReturn(withNull).when(mixedAuthoritiesAuth).getAuthorities();
        assertThat(AuthenticatedUser.isAdmin(mixedAuthoritiesAuth)).isTrue();
    }

    @Test
    void resolveEmailAndUnverifiedChecks_nullAndRawClaimEdgeCases() {
        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(null)).isFalse();
        assertThat(AuthenticatedUser.resolveEmail(null)).isNull();
        assertThat(AuthenticatedUser.normalizeEmail(null)).isNull();
        assertThat(AuthenticatedUser.normalizeEmail("not-an-email")).isNull();

        OidcUser mockedRawFalseClaim = org.mockito.Mockito.mock(OidcUser.class);
        org.mockito.Mockito.when(mockedRawFalseClaim.getEmailVerified()).thenReturn(null);
        org.mockito.Mockito.when(mockedRawFalseClaim.getClaims()).thenReturn(Map.of("email_verified", Boolean.FALSE));
        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(mockedRawFalseClaim)).isTrue();

        OidcUser mockedRawTrueClaim = org.mockito.Mockito.mock(OidcUser.class);
        org.mockito.Mockito.when(mockedRawTrueClaim.getEmailVerified()).thenReturn(null);
        org.mockito.Mockito.when(mockedRawTrueClaim.getClaims()).thenReturn(Map.of("email_verified", Boolean.TRUE));
        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(mockedRawTrueClaim)).isFalse();

        OidcUser mockedNullClaims = org.mockito.Mockito.mock(OidcUser.class);
        org.mockito.Mockito.when(mockedNullClaims.getEmailVerified()).thenReturn(null);
        org.mockito.Mockito.when(mockedNullClaims.getClaims()).thenReturn(null);
        assertThat(AuthenticatedUser.isEmailExplicitlyUnverified(mockedNullClaims)).isFalse();
    }

    private static OidcUser buildOidcUser(Map<String, Object> claims) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(3600);
        OidcIdToken idToken = new OidcIdToken("token-value", issuedAt, expiresAt, claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }

    private static Stream<Arguments> allowedEnterpriseAndFallbackOidcCases() {
        return Stream.of(
                Arguments.of(Map.of("sub", "sub-saml", "email", " Enterprise.User@Corp.com "), "enterprise.user@corp.com"),
                Arguments.of(Map.of("sub", "sub-string-true", "email", "user@corp.com", "email_verified", "true"), "user@corp.com"),
                Arguments.of(Map.of("sub", "sub-upn-1", "upn", "  Alice@Contoso.COM ", "preferred_username", "other@contoso.com"), "alice@contoso.com"),
                Arguments.of(Map.of("sub", "sub-uniq-1", "unique_name", " Bob@Contoso.com ", "preferred_username", "other@contoso.com", "email_verified", true), "bob@contoso.com"),
                Arguments.of(Map.of("sub", "sub-pref-1", "preferred_username", " Carol@Contoso.com "), "carol@contoso.com")
        );
    }

    private static Stream<Arguments> explicitlyUnverifiedOrMissingEmailOidcCases() {
        return Stream.of(
                Arguments.of(Map.of("sub", "sub-1", "email", "user@example.com", "email_verified", false), true),
                Arguments.of(Map.of("sub", "sub-2", "email", "user@example.com", "upn", "user@contoso.com", "email_verified", "false"), true),
                Arguments.of(Map.of("sub", "sub-3", "preferred_username", "victim@example.com", "email_verified", " FALSE "), true),
                Arguments.of(Map.of("sub", "sub-4", "email", "   ", "email_verified", true), false),
                Arguments.of(Map.of("sub", "sub-5", "email", "not-an-email", "upn", "also-not-email", "preferred_username", "plain-handle"), false)
        );
    }

    private static Stream<Arguments> displayNameOidcCases() {
        return Stream.of(
                Arguments.of(Map.of("sub", "sub-123", "email", "display@example.com", "email_verified", true), "display@example.com"),
                Arguments.of(Map.of("sub", "sub-123", "email", "display@example.com", "email_verified", false), null),
                Arguments.of(Map.of("sub", "sub-123", "preferred_username", "fallback.user@example.com"), "fallback.user@example.com")
        );
    }
}
