package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.ValidationRunForm;
import de.palsoftware.scim.validator.ui.dto.ValidationRunView;
import de.palsoftware.scim.validator.ui.security.AuthenticatedUser;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.ValidationRunService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ByteArrayResource;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.util.UUID;
import java.util.Map;
import java.util.HashMap;

@Controller
public class ValidationController {

    private static final String ATTR_CURRENT_USER = "currentUser";
    private static final String ATTR_CURRENT_USER_ROLE = "currentUserRole";
    private static final String ROLE_ADMIN = "Admin";
    private static final String ROLE_USER = "User";

    private final ValidationRunService validationRunService;
    private final MgmtUserService mgmtUserService;
    private final String playgroundUrl;

    public ValidationController(ValidationRunService validationRunService,
            MgmtUserService mgmtUserService,
            @org.springframework.beans.factory.annotation.Value("${app.playground.url}") String playgroundUrl) {
        this.validationRunService = validationRunService;
        this.mgmtUserService = mgmtUserService;
        this.playgroundUrl = playgroundUrl;
    }

    @GetMapping("/")
    public String index(Model model, Authentication authentication) {
        if (!model.containsAttribute("runForm")) {
            model.addAttribute("runForm", new ValidationRunForm("", "", ""));
        }
        model.addAttribute("runs", validationRunService.listRuns(actorEmail(authentication), isAdmin(authentication)));
        model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
        model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
        model.addAttribute("maxRuns", validationRunService.getMaxRunsPerUser());
        model.addAttribute("playgroundUrl", playgroundUrl);
        return "index";
    }

    @PostMapping("/runs")
    public String execute(@Valid @ModelAttribute("runForm") ValidationRunForm runForm,
            BindingResult bindingResult,
            Model model,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("runs",
                validationRunService.listRuns(actorEmail(authentication), isAdmin(authentication)));
            model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
            model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
            model.addAttribute("maxRuns", validationRunService.getMaxRunsPerUser());
            model.addAttribute("playgroundUrl", playgroundUrl);
            return "index";
        }

        ValidationRunService.ExecutionResult result = validationRunService.executeRun(runForm, actorEmail(authentication));
        ValidationRunView run = ValidationRunView.from(result.getRun());
        if (result.isOldRunDeleted()) {
            redirectAttributes.addFlashAttribute("infoMessage", 
                "An older test run was deleted to make room for this new one. Maximum allowed runs per user is " + result.getMaxRuns() + ".");
        }
        return "redirect:/runs/" + run.id();
    }

    @GetMapping("/runs/{runId}")
    public String detail(@PathVariable UUID runId, Model model, Authentication authentication) {
        try {
            model.addAttribute("run",
                    validationRunService.getRun(runId, actorEmail(authentication), isAdmin(authentication)));
            model.addAttribute("tests",
                    validationRunService.getTestResults(runId, actorEmail(authentication), isAdmin(authentication)));
        } catch (ResponseStatusException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                model.addAttribute("runNotFound", true);
            } else {
                throw e;
            }
        }
        model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
        model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
        model.addAttribute("playgroundUrl", playgroundUrl);
        return "run-detail";
    }

    @PostMapping("/runs/{runId}/delete")
    public String deleteRun(@PathVariable UUID runId, Authentication authentication) {
        validationRunService.deleteRun(runId, actorEmail(authentication), isAdmin(authentication));
        return "redirect:/";
    }

    @GetMapping(value = "/runs/{runId}/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Resource> exportRun(@PathVariable UUID runId, Authentication authentication) throws Exception {
        Object run = validationRunService.getRun(runId, actorEmail(authentication), isAdmin(authentication));
        if (run == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        Object tests = validationRunService.getTestResults(runId, actorEmail(authentication), isAdmin(authentication));
        Map<String, Object> exportData = new HashMap<>();
        exportData.put("run", run);
        exportData.put("tests", tests);

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        byte[] json = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(exportData);
        
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"validation-run-" + runId + ".json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ByteArrayResource(json));
    }

    private String actorEmail(Authentication authentication) {
        return AuthenticatedUser.email(authentication);
    }

    private boolean isAdmin(Authentication authentication) {
        return AuthenticatedUser.isAdmin(authentication);
    }

    private String currentUserRole(Authentication authentication) {
        return isAdmin(authentication) ? ROLE_ADMIN : ROLE_USER;
    }

    private String resolveDisplayName(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        String fallback = AuthenticatedUser.displayName(authentication);
        return mgmtUserService.resolveDisplayName(AuthenticatedUser.email(authentication), fallback);
    }
}
