package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.security.AuthErrorReason;
import de.palsoftware.scim.validator.ui.security.SecurityConfig;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthErrorController {

    private final String retryLoginPath;

    public AuthErrorController(ClientRegistrationRepository clientRegistrationRepository) {
        this.retryLoginPath = SecurityConfig.oidcLoginUrl(clientRegistrationRepository);
    }

    @GetMapping(SecurityConfig.AUTH_ERROR_PATH)
    public String authError(@RequestParam(name = "reason", required = false) String reason, Model model) {
        AuthErrorReason error = AuthErrorReason.fromCode(reason);
        model.addAttribute("errorTitle", error.title());
        model.addAttribute("errorMessage", error.message());
        model.addAttribute("retryLoginPath", retryLoginPath);
        return "auth-error";
    }
}
