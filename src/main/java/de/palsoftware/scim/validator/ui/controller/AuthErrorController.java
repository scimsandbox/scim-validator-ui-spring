package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.security.SecurityConfig;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthErrorController {

    @GetMapping(SecurityConfig.AUTH_ERROR_PATH)
    public String authError(@RequestParam(name = "reason", required = false) String reason, Model model) {
        String normalizedReason = reason == null ? "" : reason.trim();
        String title;
        String message;
        switch (normalizedReason) {
            case "unverified_email" -> {
                title = "Email verification required";
                message = "Please verify your email address with your identity provider before signing in.";
            }
            case "access_denied" -> {
                title = "Sign-in was denied";
                message = "Your identity provider declined the sign-in request. Make sure your account is verified and authorized.";
            }
            case "authorization_request_not_found" -> {
                title = "Sign-in session expired";
                message = "Your sign-in session could not be matched. Please start sign-in again from this address.";
            }
            case "invalid_token" -> {
                title = "Account profile incomplete";
                message = "Your identity provider did not return a valid email address required for access.";
            }
            default -> {
                title = "Sign-in failed";
                message = "Authentication could not be completed. Please try signing in again.";
            }
        }
        model.addAttribute("errorTitle", title);
        model.addAttribute("errorMessage", message);
        return "auth-error";
    }
}
