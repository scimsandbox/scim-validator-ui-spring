package de.palsoftware.scim.validator.ui.model.spec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ColourGradientInfo(
        @JsonProperty("name") String name,
        @JsonProperty("startColor") String startColor,
        @JsonProperty("endColor") String endColor,
        @JsonProperty("label") String label
) {
    public static ColourGradientInfo from(ColourGradient gradient) {
        if (gradient == null) {
            return null;
        }
        return new ColourGradientInfo(
                gradient.getName(),
                gradient.getStartColor(),
                gradient.getEndColor(),
                gradient.getLabel()
        );
    }

    public static ColourGradientInfo from(String gradientName, int score) {
        if (gradientName != null && !gradientName.isBlank()) {
            try {
                return from(ColourGradient.valueOf(gradientName.toUpperCase()));
            } catch (Exception ignored) {
            }
        }
        return from(ColourGradient.forScore(score));
    }
}
