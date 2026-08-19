package de.palsoftware.scim.validator.ui.controller;

import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteRequest;
import de.palsoftware.scim.validator.ui.dto.PlaygroundExecuteResponse;
import de.palsoftware.scim.validator.ui.security.AuthenticatedUser;
import de.palsoftware.scim.validator.ui.service.MgmtUserService;
import de.palsoftware.scim.validator.ui.service.PlaygroundExecutionService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Locale;
import java.util.Set;

@Controller
public class PlaygroundController {

    private static final String ATTR_CURRENT_USER = "currentUser";
    private static final String ATTR_CURRENT_USER_ROLE = "currentUserRole";
    private static final String ROLE_ADMIN = "Admin";
    private static final String ROLE_USER = "User";

    private static final Set<String> VALID_TOPICS = Set.of(
            "users",
            "groups",
            "resource-types",
            "schemas",
            "service-provider-config",
            "bulk",
            "search",
            "etag"
    );

    public record TopicItem(String id, String title, String icon, String summary) {}

    private static final List<TopicItem> ALL_TOPICS = List.of(
            new TopicItem("users", "Users", "👤", "Create, list, filter, update, patch, and delete User resources."),
            new TopicItem("groups", "Groups", "👥", "Manage Groups and user memberships via PUT and PATCH operations."),
            new TopicItem("resource-types", "Resource Types", "📑", "Inspect SCIM resource endpoints, schemas, and extensions."),
            new TopicItem("schemas", "Schemas", "📐", "Retrieve core User, Group, and Enterprise schema definitions."),
            new TopicItem("service-provider-config", "Service Provider Config", "⚙️", "Query supported features (PATCH, bulk, filter, sort, etag)."),
            new TopicItem("bulk", "Bulk Operations", "📦", "Execute batched transactional and non-transactional operations."),
            new TopicItem("search", ".search Endpoint", "🔍", "Execute complex POST-based filter queries without URL limits."),
            new TopicItem("etag", "ETag & Concurrency", "🏷️", "Optimistic concurrency locking and conditional HTTP requests.")
    );

    private final PlaygroundExecutionService executionService;
    private final MgmtUserService mgmtUserService;
    private final String playgroundUrl;

    public PlaygroundController(PlaygroundExecutionService executionService,
                                MgmtUserService mgmtUserService,
                                @Value("${app.playground.url}") String playgroundUrl) {
        this.executionService = executionService;
        this.mgmtUserService = mgmtUserService;
        this.playgroundUrl = playgroundUrl;
    }

    @GetMapping("/request-explorer")
    public String playgroundRoot() {
        return "redirect:/request-explorer/users";
    }

    @GetMapping("/request-explorer/{topic}")
    public String playgroundTopic(@PathVariable String topic, Model model, Authentication authentication) {
        String normalizedTopic = topic != null ? topic.toLowerCase(Locale.ROOT).trim() : "users";
        if (!VALID_TOPICS.contains(normalizedTopic)) {
            normalizedTopic = "users";
        }

        model.addAttribute("activeTopic", normalizedTopic);
        model.addAttribute("topics", ALL_TOPICS);
        model.addAttribute(ATTR_CURRENT_USER, resolveDisplayName(authentication));
        model.addAttribute(ATTR_CURRENT_USER_ROLE, currentUserRole(authentication));
        model.addAttribute("playgroundUrl", playgroundUrl);
        return "playground";
    }

    @PostMapping(value = "/api/request-explorer/execute", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<PlaygroundExecuteResponse> executeRequest(@Valid @RequestBody PlaygroundExecuteRequest request) {
        PlaygroundExecuteResponse response = executionService.execute(request);
        return ResponseEntity.ok(response);
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
