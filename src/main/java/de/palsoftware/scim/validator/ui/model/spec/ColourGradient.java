package de.palsoftware.scim.validator.ui.model.spec;

public enum ColourGradient {
    EMERALD(95, 100, "#10b981", "#059669", "Emerald", "Excellent"),
    TEAL_GREEN(85, 94, "#22c55e", "#0d9488", "Teal/Green", "Good"),
    AMBER(70, 84, "#f59e0b", "#d97706", "Amber", "Fair"),
    ORANGE(50, 69, "#f97316", "#ea580c", "Orange", "Needs Improvement"),
    RED(0, 49, "#ef4444", "#dc2626", "Red", "Ineligible / Non-Compliant");

    private final int minScore;
    private final int maxScore;
    private final String startColor;
    private final String endColor;
    private final String name;
    private final String label;

    ColourGradient(int minScore, int maxScore, String startColor, String endColor, String name, String label) {
        this.minScore = minScore;
        this.maxScore = maxScore;
        this.startColor = startColor;
        this.endColor = endColor;
        this.name = name;
        this.label = label;
    }

    public static ColourGradient forScore(int score) {
        if (score >= 95) return EMERALD;
        if (score >= 85) return TEAL_GREEN;
        if (score >= 70) return AMBER;
        if (score >= 50) return ORANGE;
        return RED;
    }

    public int getMinScore() {
        return minScore;
    }

    public int getMaxScore() {
        return maxScore;
    }

    public String getStartColor() {
        return startColor;
    }

    public String getEndColor() {
        return endColor;
    }

    public String getName() {
        return name;
    }

    public String getLabel() {
        return label;
    }

    public String cssLinearGradient() {
        return "linear-gradient(135deg, " + startColor + " 0%, " + endColor + " 100%)";
    }

    public String cssClass() {
        return "gradient-" + name().toLowerCase().replace('_', '-');
    }

    public boolean isPublishable() {
        return this != RED;
    }
}
