package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SpecRequirement(
        @JsonProperty("id") String id,
        @JsonProperty("rfc") String rfc,
        @JsonProperty("section") String section,
        @JsonProperty("title") String title,
        @JsonProperty("level") String level,
        @JsonProperty("capability") String capability,
        @JsonProperty("observability") String observability,
        @JsonProperty("disposition") String disposition,
        @JsonProperty("note") String note
) {
    public SpecRequirement {
        Objects.requireNonNull(id, "Requirement id must not be null");
        if (capability == null || capability.isBlank()) {
            capability = "none";
        } else {
            capability = capability.trim();
        }
        if (observability == null || observability.isBlank()) {
            observability = "response";
        }
        if (disposition == null || disposition.isBlank()) {
            disposition = "tested";
        }
        if (note == null) {
            note = "";
        }
        if (level != null) {
            level = level.trim().toUpperCase();
        }
    }

    /**
     * Normative RFC 2119 weight: MUST = 3, SHOULD = 2, MAY / OPTIONAL = 1.
     */
    public int getWeight() {
        if (level == null) return 1;
        return switch (level) {
            case "MUST" -> 3;
            case "SHOULD" -> 2;
            case "MAY", "OPTIONAL" -> 1;
            default -> 1;
        };
    }

    public boolean isCore() {
        return "none".equalsIgnoreCase(capability);
    }

    public boolean isOptionalCapability() {
        return !isCore();
    }

    public boolean isMust() {
        return "MUST".equalsIgnoreCase(level);
    }

    public boolean isShould() {
        return "SHOULD".equalsIgnoreCase(level);
    }

    public boolean isMayOrOptional() {
        return "MAY".equalsIgnoreCase(level) || "OPTIONAL".equalsIgnoreCase(level);
    }

    public boolean isTested() {
        return "tested".equalsIgnoreCase(disposition);
    }

    public String rfcUrl() {
        if (rfc == null || rfc.isBlank()) return null;
        if (section == null || section.isBlank()) {
            return "https://www.rfc-editor.org/rfc/rfc" + rfc;
        }
        return "https://www.rfc-editor.org/rfc/rfc" + rfc + "#section-" + section;
    }
}
