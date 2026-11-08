package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SpecRequirement(
        @JsonProperty("id") String id,
        @JsonProperty("rfc") String rfc,
        @JsonProperty("section") String section,
        @JsonProperty("subject") String subject,
        @JsonProperty("level") String level,
        @JsonProperty("quote") String quote,
        @JsonProperty("summary") String summary,
        @JsonProperty("area") String area,
        @JsonProperty("capability") String capability,
        @JsonProperty("disposition") String disposition
) {
    public static final String CORE_CAPABILITY = "core";

    public SpecRequirement(
            String id,
            String rfc,
            String section,
            String subject,
            String level,
            String quote,
            String area,
            String capability,
            String disposition
    ) {
        this(id, rfc, section, subject, level, quote, null, area, capability, disposition);
    }

    public SpecRequirement {
        Objects.requireNonNull(id, "Requirement id must not be null");
        if (capability == null || capability.isBlank()) {
            capability = CORE_CAPABILITY;
        } else {
            capability = capability.trim();
        }
        if (disposition == null || disposition.isBlank()) {
            disposition = "tested";
        }
        if (subject == null) {
            subject = "";
        }
        if (quote == null) {
            quote = "";
        }
        if (summary == null || summary.isBlank()) {
            summary = quote;
        } else {
            summary = summary.trim();
        }
        if (area == null) {
            area = "";
        }
        if (level != null) {
            level = level.trim().toUpperCase();
        }
    }

    /**
     * Display text for matrices and reports: the self-contained 1-sentence summary (falling back to verbatim quote).
     */
    public String title() {
        return summary;
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
        return CORE_CAPABILITY.equalsIgnoreCase(capability);
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

    /**
     * True for dispositions that take part in scoring. The generated catalogs mark requirements
     * as "unassigned" or "gap" until a test covers them; those still count (UNTESTED if nothing ran),
     * only "optional" and "na" are handled specially by the scoring.
     */
    public boolean isScored() {
        return !"optional".equalsIgnoreCase(disposition) && !"na".equalsIgnoreCase(disposition);
    }

    public String rfcUrl() {
        return formatRfcUrl(rfc, section);
    }

    public String rfcLabel() {
        return formatRfcLabel(rfc, section);
    }

    public static String formatRfcUrl(String rfc, String section) {
        if (rfc == null || rfc.isBlank()) {
            return null;
        }
        String trimmedRfc = rfc.trim();
        if (section == null || section.isBlank()) {
            return "https://www.rfc-editor.org/rfc/rfc" + trimmedRfc;
        }
        return "https://www.rfc-editor.org/rfc/rfc" + trimmedRfc + "#section-" + section.trim();
    }

    public static String formatRfcLabel(String rfc, String section) {
        if (rfc == null || rfc.isBlank()) {
            return "";
        }
        String trimmedRfc = rfc.trim();
        if (section == null || section.isBlank()) {
            return "RFC " + trimmedRfc;
        }
        return "RFC " + trimmedRfc + " §" + section.trim();
    }
}
