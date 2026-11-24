package de.palsoftware.scim.validator.ui.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public enum AuthErrorReason {

    ACCESS_DENIED(
            OAuth2ErrorCodes.ACCESS_DENIED,
            "Sign-in was denied",
            "Your identity provider declined the sign-in request. Make sure your account is authorized.",
            true),
    AUTHORIZATION_REQUEST_NOT_FOUND(
            "authorization_request_not_found",
            "Sign-in session expired",
            "Your sign-in session could not be matched. Please start sign-in again from this address.",
            false),
    MISSING_EMAIL(
            "missing_email",
            "Account profile incomplete",
            "Your identity provider did not return a valid email address required for access.",
            true),
    AUTHENTICATION_FAILED(
            "authentication_failed",
            "Sign-in failed",
            "Authentication could not be completed. Please try signing in again.",
            false);

    private final String code;
    private final String title;
    private final String message;
    private final boolean forceReauthentication;

    AuthErrorReason(String code, String title, String message, boolean forceReauthentication) {
        this.code = code;
        this.title = title;
        this.message = message;
        this.forceReauthentication = forceReauthentication;
    }

    public String code() {
        return code;
    }

    public String title() {
        return title;
    }

    public String message() {
        return message;
    }

    public boolean forceReauthentication() {
        return forceReauthentication;
    }

    public static AuthErrorReason fromCode(String code) {
        if (code == null) {
            return AUTHENTICATION_FAILED;
        }
        String normalized = code.trim();
        for (AuthErrorReason candidate : values()) {
            if (candidate.code.equals(normalized)) {
                return candidate;
            }
        }
        return AUTHENTICATION_FAILED;
    }

    public static AuthErrorReason fromException(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2Ex) {
            return fromCode(oauth2Ex.getError().getErrorCode());
        }
        return AUTHENTICATION_FAILED;
    }
}
