package de.palsoftware.scim.validator.ui.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Outbound SSRF target URL policy shared by the SCIM Playground and SCIM Compliance validation runs.
 *
 * <p>By default ({@code app.security.allow-localhost-targets=false}), only {@code https} URLs
 * targeting public, globally routable hostnames and IP addresses are permitted. Loopback,
 * unspecified, RFC 1918 private, link-local / cloud metadata, CGNAT, IPv6 ULA, multicast,
 * NAT64, single-label hostnames, and internal service/cluster domains are rejected. The
 * configured management port (default {@code 9090}) is always rejected on loopback targets.</p>
 */
@Component
public class TargetUrlPolicy {

    public static final int DEFAULT_MANAGEMENT_PORT = 9090;
    public static final HostAddressResolver DEFAULT_RESOLVER = PinnedTargetHttpSupport::resolveUnpinned;
    public static final TargetUrlPolicy DEFAULT_STRICT = new TargetUrlPolicy(false);

    private static final Set<String> FORBIDDEN_HOST_SUFFIXES = Set.of(
            ".localhost",
            ".local",
            ".internal",
            ".svc",
            ".cluster.local"
    );
    private static final Set<String> FORBIDDEN_EXACT_HOSTS = Set.of(
            "local",
            "internal",
            "svc",
            "metadata.google.internal"
    );

    @FunctionalInterface
    public interface HostAddressResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /**
     * Validated outbound target with its normalized bare hostname and pinned IP addresses.
     */
    public record ResolvedTarget(URI uri, String host, List<InetAddress> addresses) {
        public ResolvedTarget {
            Objects.requireNonNull(uri, "URI must not be null");
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Resolved target host must not be blank");
            }
            Objects.requireNonNull(addresses, "Resolved addresses must not be null");
            addresses = List.copyOf(addresses);
            if (addresses.isEmpty()) {
                throw new IllegalArgumentException("Resolved addresses must not be empty");
            }
        }
    }

    private record ParsedTarget(
            URI uri,
            String scheme,
            String bareHost,
            int effectivePort,
            boolean explicitLoopbackTarget,
            InetAddress literalAddress
    ) {}

    private final boolean allowLocalhostTargets;
    private final int managementPort;
    private final HostAddressResolver resolver;

    public TargetUrlPolicy(boolean allowLocalhostTargets) {
        this(allowLocalhostTargets, DEFAULT_MANAGEMENT_PORT, DEFAULT_RESOLVER);
    }

    @Autowired
    public TargetUrlPolicy(
            @Value("${app.security.allow-localhost-targets:false}") boolean allowLocalhostTargets,
            @Value("${management.server.port:9090}") int managementPort) {
        this(allowLocalhostTargets, managementPort, DEFAULT_RESOLVER);
    }

    public TargetUrlPolicy(boolean allowLocalhostTargets, HostAddressResolver resolver) {
        this(allowLocalhostTargets, DEFAULT_MANAGEMENT_PORT, resolver);
    }

    public TargetUrlPolicy(boolean allowLocalhostTargets, int managementPort, HostAddressResolver resolver) {
        this.allowLocalhostTargets = allowLocalhostTargets;
        this.managementPort = managementPort;
        this.resolver = Objects.requireNonNull(resolver, "HostAddressResolver must not be null");
    }

    public boolean isAllowLocalhostTargets() {
        return allowLocalhostTargets;
    }

    public int getManagementPort() {
        return managementPort;
    }

    /**
     * Validates URL syntax, scheme, userinfo, hostname rules, IP literals, and loopback management-port
     * restrictions without performing any DNS lookups.
     */
    public URI validateSyntax(String url) {
        return parseAndValidateSyntax(url).uri();
    }

    /**
     * Validates URL syntax and resolves the target hostname exactly once, returning the validated
     * {@link ResolvedTarget} with pinned IP addresses for connection-time binding.
     */
    public ResolvedTarget resolve(String url) {
        ParsedTarget parsed = parseAndValidateSyntax(url);
        List<InetAddress> addresses = parsed.literalAddress() != null
                ? List.of(parsed.literalAddress())
                : resolveAndValidateAddresses(
                        parsed.bareHost(),
                        parsed.effectivePort(),
                        allowLocalhostTargets && parsed.explicitLoopbackTarget());
        return new ResolvedTarget(parsed.uri(), parsed.bareHost(), addresses);
    }

    public URI validateUri(String url) {
        return resolve(url).uri();
    }

    /**
     * Parses {@code fullUrl}, validates scheme/userinfo/port syntax, and verifies it shares the exact
     * same origin {@code (scheme, normalized bareHost, effectivePort)} as {@code baseTarget} without
     * performing an additional DNS lookup.
     */
    public URI validateSameOriginUri(ResolvedTarget baseTarget, String fullUrl) {
        Objects.requireNonNull(baseTarget, "ResolvedTarget must not be null");
        if (fullUrl == null || fullUrl.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        URI targetUri = parseUri(fullUrl.trim());
        String targetScheme = normalizeScheme(targetUri.getScheme());
        validatePortRange(targetUri.getPort());
        if (targetUri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Invalid URL: userinfo credentials in target URL are not allowed");
        }

        String normalizedHost = normalizeHost(targetUri.getHost());
        boolean targetIpv6Literal = normalizedHost.startsWith("[") && normalizedHost.endsWith("]");
        String targetBareHost = stripIpv6Brackets(normalizedHost);
        if (targetBareHost.contains("%")) {
            throw new IllegalArgumentException("Invalid URL: IPv6 zone identifiers are not allowed");
        }
        String canonicalTargetHost = canonicalizeBareHostForComparison(targetBareHost, targetIpv6Literal);
        String canonicalBaseHost = PinnedTargetHttpSupport.normalizeDnsHost(baseTarget.host());

        String baseScheme = normalizeScheme(baseTarget.uri().getScheme());
        int baseEffectivePort = effectivePort(baseScheme, baseTarget.uri().getPort());
        int targetEffectivePort = effectivePort(targetScheme, targetUri.getPort());

        if (!baseScheme.equals(targetScheme)
                || !canonicalBaseHost.equals(canonicalTargetHost)
                || baseEffectivePort != targetEffectivePort) {
            throw new IllegalArgumentException("Invalid URL: endpoint must remain on the configured target origin");
        }
        return targetUri;
    }

    static InetAddress parseIpv6Literal(String bareHost) {
        try {
            return InetAddress.ofLiteral(bareHost);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address", ex);
        }
    }

    private static String canonicalizeBareHostForComparison(String bareHost, boolean isIpv6Literal) {
        if (isIpv6Literal) {
            return parseIpv6Literal(bareHost).getHostAddress().toLowerCase(Locale.ROOT);
        }
        if (isCanonicalIpv4Literal(bareHost)) {
            return InetAddress.ofLiteral(bareHost).getHostAddress().toLowerCase(Locale.ROOT);
        }
        return bareHost;
    }

    private ParsedTarget parseAndValidateSyntax(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        URI uri = parseUri(url.trim());
        String scheme = normalizeScheme(uri.getScheme());
        validatePortRange(uri.getPort());
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Invalid URL: userinfo credentials in target URL are not allowed");
        }

        String normalizedHost = normalizeHost(uri.getHost());
        boolean isIpv6Literal = normalizedHost.startsWith("[") && normalizedHost.endsWith("]");
        String bareHost = stripIpv6Brackets(normalizedHost);

        if (bareHost.contains("%")) {
            throw new IllegalArgumentException("Invalid URL: IPv6 zone identifiers are not allowed");
        }

        InetAddress literalAddress = null;
        if (isIpv6Literal) {
            literalAddress = parseIpv6Literal(bareHost);
        } else if (isCanonicalIpv4Literal(bareHost)) {
            literalAddress = InetAddress.ofLiteral(bareHost);
        }

        boolean explicitLoopbackTarget = "localhost".equals(normalizedHost)
                || "127.0.0.1".equals(normalizedHost)
                || (isIpv6Literal
                        && literalAddress instanceof Inet6Address
                        && literalAddress.isLoopbackAddress());
        int effectivePort = effectivePort(scheme, uri.getPort());

        if ((explicitLoopbackTarget || (literalAddress != null && literalAddress.isLoopbackAddress()))
                && isForbiddenManagementPort(effectivePort)) {
            throw new IllegalArgumentException(
                    "Invalid URL: management port " + managementPort + " is not allowed");
        }

        validateSchemeAndHostname(scheme, normalizedHost, bareHost, isIpv6Literal, explicitLoopbackTarget);
        if (literalAddress != null) {
            validateAddress(literalAddress, allowLocalhostTargets && explicitLoopbackTarget);
        }
        String canonicalBareHost = literalAddress != null
                ? literalAddress.getHostAddress().toLowerCase(Locale.ROOT)
                : bareHost;
        return new ParsedTarget(uri, scheme, canonicalBareHost, effectivePort, explicitLoopbackTarget, literalAddress);
    }

    private static String stripIpv6Brackets(String normalizedHost) {
        if (normalizedHost.startsWith("[") && normalizedHost.endsWith("]")) {
            return normalizedHost.substring(1, normalizedHost.length() - 1);
        }
        return normalizedHost;
    }

    private static URI parseUri(String trimmedUrl) {
        try {
            return new URI(trimmedUrl);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid URL: malformed target URI", ex);
        }
    }

    private static String normalizeScheme(String rawScheme) {
        String scheme = rawScheme != null ? rawScheme.toLowerCase(Locale.ROOT) : null;
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IllegalArgumentException("Invalid URL: only http and https targets are allowed");
        }
        return scheme;
    }

    private static void validatePortRange(int port) {
        if (port != -1 && (port < 1 || port > 65535)) {
            throw new IllegalArgumentException("Invalid URL: port out of valid range");
        }
    }

    static int effectivePort(String normalizedScheme, int rawPort) {
        if (rawPort != -1) {
            return rawPort;
        }
        return "https".equals(normalizedScheme) ? 443 : 80;
    }

    private boolean isForbiddenManagementPort(int effectivePort) {
        return managementPort > 0 && effectivePort == managementPort;
    }

    private static String normalizeHost(String rawHost) {
        if (rawHost == null || rawHost.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must include a host");
        }
        String host = rawHost.trim().toLowerCase(Locale.ROOT);
        if (!host.startsWith("[")) {
            while (host.endsWith(".")) {
                host = host.substring(0, host.length() - 1);
            }
        }
        if (host.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must include a host");
        }
        return host;
    }

    private void validateSchemeAndHostname(
            String scheme,
            String normalizedHost,
            String bareHost,
            boolean isIpv6Literal,
            boolean explicitLoopbackTarget) {
        if (explicitLoopbackTarget) {
            if (!allowLocalhostTargets) {
                throw new IllegalArgumentException("Invalid URL: localhost targets are not allowed");
            }
            return;
        }

        if ("http".equals(scheme)) {
            if (allowLocalhostTargets) {
                throw new IllegalArgumentException(
                        "Invalid URL: plain http is only allowed for localhost targets, use https");
            }
            throw new IllegalArgumentException("Invalid URL: only https targets are allowed");
        }

        if ("localhost".equals(normalizedHost) || normalizedHost.endsWith(".localhost")) {
            throw new IllegalArgumentException("Invalid URL: localhost targets are not allowed");
        }
        if (isForbiddenInternalDomain(normalizedHost)) {
            throw new IllegalArgumentException("Invalid URL: internal or cluster hostnames are not allowed");
        }

        if (!isIpv6Literal && !isCanonicalIpv4Literal(bareHost)) {
            if (!bareHost.contains(".")) {
                throw new IllegalArgumentException("Invalid URL: single-label hostnames are not allowed");
            }
            if (hasNonStandardNumericHostEncoding(bareHost)) {
                throw new IllegalArgumentException("Invalid URL: non-standard numeric IP encodings are not allowed");
            }
        }
    }

    private static boolean isForbiddenInternalDomain(String normalizedHost) {
        if (FORBIDDEN_EXACT_HOSTS.contains(normalizedHost)) {
            return true;
        }
        for (String suffix : FORBIDDEN_HOST_SUFFIXES) {
            if (normalizedHost.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCanonicalIpv4Literal(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return false;
            }
            int value = parseDecimalOctet(part);
            if (value < 0 || value > 255) {
                return false;
            }
        }
        return true;
    }

    private static int parseDecimalOctet(String part) {
        int value = 0;
        for (int i = 0; i < part.length(); i++) {
            char ch = part.charAt(i);
            if (ch < '0' || ch > '9') {
                return -1;
            }
            value = (value * 10) + (ch - '0');
        }
        return value;
    }

    private static boolean hasNonStandardNumericHostEncoding(String host) {
        int lastDot = host.lastIndexOf('.');
        String tld = lastDot >= 0 ? host.substring(lastDot + 1) : host;
        if (tld.isEmpty()) {
            return true;
        }
        boolean allDigits = true;
        for (int i = 0; i < tld.length(); i++) {
            if (!Character.isDigit(tld.charAt(i))) {
                allDigits = false;
                break;
            }
        }
        return allDigits || tld.startsWith("0x");
    }

    private List<InetAddress> resolveAndValidateAddresses(
            String bareHost,
            int effectivePort,
            boolean allowLoopback) {
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(bareHost);
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid URL: target host could not be resolved", ex);
        }
        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("Invalid URL: target host resolved to no addresses");
        }
        List<InetAddress> validated = new ArrayList<>(addresses.length);
        for (InetAddress address : addresses) {
            if (address == null) {
                throw new IllegalArgumentException("Invalid URL: invalid resolved address");
            }
            if (address.isLoopbackAddress() && isForbiddenManagementPort(effectivePort)) {
                throw new IllegalArgumentException(
                        "Invalid URL: management port " + managementPort + " is not allowed");
            }
            validateAddress(address, allowLoopback);
            validated.add(address);
        }
        return List.copyOf(validated);
    }

    private static void validateAddress(InetAddress address, boolean allowLoopback) {
        if (address instanceof Inet4Address) {
            validateIpv4Bytes(address.getAddress(), allowLoopback);
            return;
        }
        if (address instanceof Inet6Address inet6) {
            validateIpv6Bytes(inet6.getAddress(), allowLoopback);
            return;
        }
        throw new IllegalArgumentException("Invalid URL: unsupported target IP address family");
    }

    private static void validateIpv4Bytes(byte[] bytes, boolean allowLoopback) {
        int b0 = bytes[0] & 0xFF;
        int b1 = bytes[1] & 0xFF;
        int b2 = bytes[2] & 0xFF;

        if (b0 == 127) {
            if (!allowLoopback) {
                throw new IllegalArgumentException("Invalid URL: loopback target addresses are not allowed");
            }
            return;
        }
        if (allowLoopback) {
            throw new IllegalArgumentException("Invalid URL: localhost target resolved to non-loopback address");
        }
        if (b0 == 0) {
            throw new IllegalArgumentException("Invalid URL: unspecified target addresses are not allowed");
        }
        if (b0 == 10
                || (b0 == 172 && (b1 & 0xF0) == 16)
                || (b0 == 192 && b1 == 168)) {
            throw new IllegalArgumentException("Invalid URL: private RFC 1918 target addresses are not allowed");
        }
        if (b0 == 169 && b1 == 254) {
            throw new IllegalArgumentException("Invalid URL: link-local and metadata target addresses are not allowed");
        }
        if (b0 == 100 && (b1 & 0xC0) == 64) {
            throw new IllegalArgumentException("Invalid URL: CGNAT target addresses are not allowed");
        }
        if ((b0 == 192 && b1 == 0 && b2 == 0)
                || (b0 == 198 && (b1 == 18 || b1 == 19))
                || (b0 & 0xF0) == 224
                || (b0 & 0xF0) == 240) {
            throw new IllegalArgumentException("Invalid URL: multicast or reserved target addresses are not allowed");
        }
    }

    private static void validateIpv6Bytes(byte[] bytes, boolean allowLoopback) {
        if (isIpv6LoopbackBytes(bytes)) {
            if (!allowLoopback) {
                throw new IllegalArgumentException("Invalid URL: loopback target addresses are not allowed");
            }
            return;
        }
        if (allowLoopback) {
            throw new IllegalArgumentException("Invalid URL: localhost target resolved to non-loopback address");
        }
        if (isIpv6UnspecifiedOrIpv4CompatiblePrefix(bytes)) {
            throw new IllegalArgumentException("Invalid URL: unspecified or IPv4-compatible IPv6 target addresses are not allowed");
        }

        int b0 = bytes[0] & 0xFF;
        int b1 = bytes[1] & 0xFF;
        int b2 = bytes[2] & 0xFF;
        int b3 = bytes[3] & 0xFF;

        if ((b0 & 0xFE) == 0xFC) {
            throw new IllegalArgumentException("Invalid URL: IPv6 ULA target addresses are not allowed");
        }
        if (b0 == 0xFE && ((b1 & 0xC0) == 0x80 || (b1 & 0xC0) == 0xC0)) {
            throw new IllegalArgumentException("Invalid URL: IPv6 link-local or site-local target addresses are not allowed");
        }
        if (b0 == 0xFF) {
            throw new IllegalArgumentException("Invalid URL: multicast target addresses are not allowed");
        }
        if (b0 == 0x00 && b1 == 0x64 && b2 == 0xFF && b3 == 0x9B) {
            throw new IllegalArgumentException("Invalid URL: NAT64 target addresses are not allowed");
        }
    }

    private static boolean isIpv6LoopbackBytes(byte[] bytes) {
        for (int i = 0; i < 15; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[15] == 1;
    }

    private static boolean isIpv6UnspecifiedOrIpv4CompatiblePrefix(byte[] bytes) {
        for (int i = 0; i < 12; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
