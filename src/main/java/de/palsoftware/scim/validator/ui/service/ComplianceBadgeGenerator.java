package de.palsoftware.scim.validator.ui.service;

import de.palsoftware.scim.validator.ui.model.spec.ColourGradient;
import org.springframework.stereotype.Service;

@Service
public class ComplianceBadgeGenerator {

    public String generate(int score, int compliantCaps, int totalCaps) {
        return generateBadgeSvg(score, compliantCaps, totalCaps, "b");
    }

    public String generate(int score, int compliantCaps, int totalCaps, String badgeId) {
        return generateBadgeSvg(score, compliantCaps, totalCaps, badgeId, false);
    }

    public String generate(int score, int compliantCaps, int totalCaps, String badgeId, boolean isSample) {
        return generateBadgeSvg(score, compliantCaps, totalCaps, badgeId, isSample);
    }

    /**
     * Generates a standard shields.io compatible SVG badge with exact colour gradient.
     *
     * @param score         Core RFC Conformance score (0 to 100)
     * @param compliantCaps Count of compliant capabilities (0 to 10)
     * @param totalCaps     Total capabilities (10)
     * @param badgeId       Short unique identifier for gradient and clipPath elements
     * @return Complete, standalone SVG markup
     */
    public static String generateBadgeSvg(int score, int compliantCaps, int totalCaps, String badgeId) {
        return generateBadgeSvg(score, compliantCaps, totalCaps, badgeId, false);
    }

    public static String generateBadgeSvg(int score, int compliantCaps, int totalCaps, String badgeId, boolean isSample) {
        ColourGradient gradient = ColourGradient.forScore(score);
        String cleaned = (badgeId != null) ? badgeId.replaceAll("[^a-zA-Z0-9_-]", "") : "";
        String safeId = cleaned.isBlank() ? "def" : cleaned;

        String labelText = "SCIM 2.0";
        String ariaLabel = isSample
                ? ("SCIM 2.0 (sample): " + score + "% · " + compliantCaps + "/" + totalCaps)
                : (labelText + ": " + score + "% · " + compliantCaps + "/" + totalCaps + " caps");
        String descText = isSample
                ? String.format("SCIM 2.0 sample compliance scorecard fixture: %d%% Core Conformance, %d/%d capabilities", score, compliantCaps, totalCaps)
                : String.format("SCIM 2.0 compliance scorecard: %d%% Core Conformance, %d/%d capabilities", score, compliantCaps, totalCaps);
        String valueText = score + "% · " + compliantCaps + "/" + totalCaps + (isSample ? " sample" : " caps");

        int leftWidth = 60;
        int leftTextLength = 480;
        int leftCenterX = 305;

        // Estimate character metrics for valueText
        int estimatedWidth = estimateTextWidth(valueText);
        int rightTextLength = estimatedWidth * 10;
        int rightWidth = Math.max(92, estimatedWidth + 14);
        int totalWidth = leftWidth + rightWidth;
        int rightCenterX = (leftWidth * 10) + ((rightWidth * 10) / 2);

        String gradId = "scim-g-" + safeId;
        String clipId = "scim-c-" + safeId;
        String overlayId = "scim-o-" + safeId;

        return """
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="20" viewBox="0 0 %d 20" role="img" aria-label="%s">
  <title>%s</title>
  <desc>%s</desc>
  <defs>
    <linearGradient id="%s" x1="0%%" y1="0%%" x2="100%%" y2="100%%">
      <stop offset="0%%" stop-color="%s"/>
      <stop offset="100%%" stop-color="%s"/>
    </linearGradient>
    <linearGradient id="%s" x1="0" y1="0" x2="0" y2="100%%">
      <stop offset="0%%" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="100%%" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="%s">
      <rect width="%d" height="20" rx="3" fill="#fff"/>
    </clipPath>
  </defs>
  <g clip-path="url(#%s)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="url(#%s)"/>
    <rect width="%d" height="20" fill="url(#%s)"/>
  </g>
  <g aria-hidden="true" fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
    <text x="%d" y="140" transform="scale(.1)" fill="#fff" textLength="%d">%s</text>
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
    <text x="%d" y="140" transform="scale(.1)" fill="#fff" textLength="%d">%s</text>
  </g>
</svg>
""".formatted(
                totalWidth, totalWidth, ariaLabel,
                ariaLabel,
                descText,
                gradId, gradient.getStartColor(), gradient.getEndColor(),
                overlayId,
                clipId, totalWidth,
                clipId,
                leftWidth,
                leftWidth, rightWidth, gradId,
                totalWidth, overlayId,
                leftCenterX, leftTextLength, labelText,
                leftCenterX, leftTextLength, labelText,
                rightCenterX, rightTextLength, valueText,
                rightCenterX, rightTextLength, valueText
        ).trim() + "\n";
    }

    private static int estimateTextWidth(String text) {
        if (text == null) return 0;
        double w = 0.0;
        for (char c : text.toCharArray()) {
            switch (c) {
                case '1', 'i', 'l', '|', ':', '.', ' ' -> w += 4.5;
                case '0', '2', '3', '4', '5', '6', '7', '8', '9' -> w += 7.0;
                case '%' -> w += 11.0;
                case '·' -> w += 5.0;
                case '/' -> w += 5.5;
                case 'c', 'a', 'p', 's', 'e' -> w += 6.5;
                case 'm' -> w += 8.0;
                default -> w += 7.0;
            }
        }
        return (int) Math.round(w);
    }
}
