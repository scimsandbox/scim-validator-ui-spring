package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.util.BaseUrl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Exposes the public website base URL to every view the page controllers render, which is what the
 * What's New dock link and feed are built from. Done here rather than per handler so that no view
 * path, such as the form re-render in {@code ValidationController#execute}, can forget it and emit
 * {@code href="null/#news"}.
 *
 * <p>The value is required configuration; a missing, blank or malformed value fails startup.
 */
@ControllerAdvice(assignableTypes = {ValidationController.class, PlaygroundController.class})
public class WebsiteUrlAdvice {

    private final String websiteUrl;

    public WebsiteUrlAdvice(@Value("${app.compliance.public-base-url}") String websiteUrl) {
        this.websiteUrl = BaseUrl.require("app.compliance.public-base-url (APP_COMPLIANCE_PUBLIC_BASE_URL)", websiteUrl);
    }

    @ModelAttribute("websiteUrl")
    public String websiteUrl() {
        return websiteUrl;
    }
}
