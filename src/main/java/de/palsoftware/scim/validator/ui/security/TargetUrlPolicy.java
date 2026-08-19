package de.palsoftware.scim.validator.ui.security;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

/**
 * Outbound target policy shared by the playground and by validation runs.
 *
 * <p>This is not an SSRF control: pointing the tools at an arbitrary SCIM server is their purpose,
 * so every https target is allowed. What it does enforce is that credentials never leave over a
 * plaintext connection - plain http is refused except for loopback, which is there for the test
 * suite and for running a UI directly on a developer machine. Inside a container loopback is the
 * container itself, so the exemption exposes nothing internal.
 */
public final class TargetUrlPolicy {

    /** URI.getHost() keeps the brackets on an IPv6 literal, so the loopback entry carries them too. */
    private static final Set<String> LOCALHOST_NAMES = Set.of("localhost", "127.0.0.1", "[::1]");

    private TargetUrlPolicy() {
    }

    public static URI validate(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        URI uri = URI.create(url.trim());
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : null;
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("Invalid URL: only http and https targets are allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must include a host");
        }
        if ("https".equals(scheme) || LOCALHOST_NAMES.contains(host.toLowerCase(Locale.ROOT))) {
            return uri;
        }
        throw new IllegalArgumentException(
                "Invalid URL: plain http is only allowed for localhost targets, use https");
    }
}
