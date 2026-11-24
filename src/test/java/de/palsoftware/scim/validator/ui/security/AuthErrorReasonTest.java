package de.palsoftware.scim.validator.ui.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;

class AuthErrorReasonTest {

    @Test
    void fromCode_resolvesAllKnownReasonsAndFallsBackForNullBlankOrUnknown() {
        for (AuthErrorReason reason : AuthErrorReason.values()) {
            assertThat(AuthErrorReason.fromCode(reason.code())).isEqualTo(reason);
            assertThat(AuthErrorReason.fromCode("  " + reason.code() + "  ")).isEqualTo(reason);
            assertThat(reason.title()).isNotBlank();
            assertThat(reason.message()).isNotBlank();
        }

        assertThat(AuthErrorReason.fromCode(null)).isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
        assertThat(AuthErrorReason.fromCode("   ")).isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
        assertThat(AuthErrorReason.fromCode("unknown_error")).isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
        assertThat(AuthErrorReason.fromCode("unverified_email")).isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
    }

    @Test
    void fromException_mapsOAuth2ErrorCodesAndDefaultsForOtherExceptions() {
        assertThat(AuthErrorReason.fromException(
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED))))
                .isEqualTo(AuthErrorReason.ACCESS_DENIED);
        assertThat(AuthErrorReason.fromException(
                new OAuth2AuthenticationException(new OAuth2Error("authorization_request_not_found"))))
                .isEqualTo(AuthErrorReason.AUTHORIZATION_REQUEST_NOT_FOUND);
        assertThat(AuthErrorReason.fromException(
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN))))
                .isEqualTo(AuthErrorReason.INVALID_TOKEN);
        assertThat(AuthErrorReason.fromException(
                new OAuth2AuthenticationException(new OAuth2Error("unexpected_code"))))
                .isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
        assertThat(AuthErrorReason.fromException(new BadCredentialsException("bad")))
                .isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
        assertThat(AuthErrorReason.fromException(null))
                .isEqualTo(AuthErrorReason.AUTHENTICATION_FAILED);
    }
}
