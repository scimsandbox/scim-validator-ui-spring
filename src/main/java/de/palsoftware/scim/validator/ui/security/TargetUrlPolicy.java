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
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Outbound SSRF target URL policy shared by the SCIM Playground and SCIM Compliance validation runs.
 *
 * <p>By default ({@code app.security.allow-localhost-targets=false}), only {@code https} URLs
 * targeting public, globally routable hostnames and IP addresses are permitted. Loopback,
 * unspecified, RFC 1918 private, link-local / cloud metadata, CGNAT, IPv6 ULA, multicast,
 * NAT64, IPv4-mapped IPv6, single-label hostnames, and internal service/cluster domains are
 * rejected. Management port {@code 9090} is unconditionally rejected in all modes.</p>
 */
@Component
public class TargetUrlPolicy {

    private static final int FORBIDDEN_MANAGEMENT_PORT = 9090;
    private static final Set<String> LOOPBACK_LITERALS_AND_NAMES = Set.of("localhost", "127.0.0.1", "[::1]");
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

    private final boolean allowLocalhostTargets;
    private final HostAddressResolver resolver;

    @Autowired
    public TargetUrlPolicy(@Value("${app.security.allow-localhost-targets:false}") boolean allowLocalhostTargets) {
        this(allowLocalhostTargets, InetAddress::getAllByName);
    }

    public TargetUrlPolicy(boolean allowLocalhostTargets, HostAddressResolver resolver) {
        this.allowLocalhostTargets = allowLocalhostTargets;
        this.resolver = Objects.requireNonNull(resolver, "HostAddressResolver must not be null");
    }

    public boolean isAllowLocalhostTargets() {
        return allowLocalhostTargets;
    }

    /**
     * Static fail-closed validation using production defaults ({@code allowLocalhostTargets = false}).
     */
    public static URI validate(String url) {
        return new TargetUrlPolicy(false).validateUri(url);
    }

    public URI validateUri(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Invalid URL: target must not be empty");
        }
        URI uri = parseUri(url.trim());
        String scheme = normalizeScheme(uri.getScheme());
        validatePort(uri.getPort());
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Invalid URL: userinfo credentials in target URL are not allowed");
        }

        String normalizedHost = normalizeHost(uri.getHost());
        boolean isIpv6Literal = normalizedHost.startsWith("[") && normalizedHost.endsWith("]");
        String bareHost = isIpv6Literal
                ? normalizedHost.substring(1, normalizedHost.length() - 1)
                : normalizedHost;

        if (bareHost.contains("%")) {
            throw new IllegalArgumentException("Invalid URL: IPv6 zone identifiers are not allowed");
        }
        if (isIpv6Literal) {
            validateIpv6LiteralSyntax(bareHost);
        }

        boolean explicitLoopbackTarget = LOOPBACK_LITERALS_AND_NAMES.contains(normalizedHost);
        validateSchemeAndHostname(scheme, normalizedHost, bareHost, isIpv6Literal, explicitLoopbackTarget);
        validateResolvedAddresses(bareHost, allowLocalhostTargets && explicitLoopbackTarget);
        return uri;
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

    private static void validatePort(int port) {
        if (port == FORBIDDEN_MANAGEMENT_PORT) {
            throw new IllegalArgumentException("Invalid URL: management port 9090 is not allowed");
        }
        if (port != -1 && (port < 1 || port > 65535)) {
            throw new IllegalArgumentException("Invalid URL: port out of valid range");
        }
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

    private void validateResolvedAddresses(String bareHost, boolean allowLoopback) {
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(bareHost);
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid URL: target host could not be resolved", ex);
        }
        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("Invalid URL: target host resolved to no addresses");
        }
        for (InetAddress address : addresses) {
            if (address == null) {
                throw new IllegalArgumentException("Invalid URL: invalid resolved address");
            }
            validateAddress(address, allowLoopback);
        }
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
        if (isIpv4MappedIpv6Bytes(bytes)) {
            throw new IllegalArgumentException("Invalid URL: IPv4-mapped IPv6 target addresses are not allowed");
        }
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

    /**
     * Inspects raw IPv6 literal syntax before {@link InetAddress} resolution because the JDK
     * transparently converts {@code ::ffff:x.y.z.w} literals into {@link Inet4Address} instances.
     */
    private static void validateIpv6LiteralSyntax(String bareIpv6) {
        byte[] rawBytes = parseIpv6LiteralBytes(bareIpv6);
        if (isIpv4MappedIpv6Bytes(rawBytes)) {
            throw new IllegalArgumentException("Invalid URL: IPv4-mapped IPv6 target addresses are not allowed");
        }
        if (!isIpv6LoopbackBytes(rawBytes) && isIpv6UnspecifiedOrIpv4CompatiblePrefix(rawBytes)) {
            throw new IllegalArgumentException("Invalid URL: unspecified or IPv4-compatible IPv6 target addresses are not allowed");
        }
    }

    private static boolean isIpv4MappedIpv6Bytes(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF;
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

    private static byte[] parseIpv6LiteralBytes(String literal) {
        String candidate = literal;
        byte[] trailingIpv4 = null;
        int lastColon = candidate.lastIndexOf(':');
        if (lastColon >= 0 && candidate.indexOf('.', lastColon) > 0) {
            String ipv4Tail = candidate.substring(lastColon + 1);
            trailingIpv4 = parseIpv4Tail(ipv4Tail);
            candidate = candidate.substring(0, lastColon + 1) + "0:0";
        }

        String[] doubleColonSplit = candidate.split("::", -1);
        if (doubleColonSplit.length > 2) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address");
        }

        String[] headParts = doubleColonSplit[0].isEmpty() ? new String[0] : doubleColonSplit[0].split(":", -1);
        String[] tailParts = (doubleColonSplit.length == 2 && !doubleColonSplit[1].isEmpty())
                ? doubleColonSplit[1].split(":", -1)
                : new String[0];

        int totalGroups = headParts.length + tailParts.length;
        if ((doubleColonSplit.length == 1 && totalGroups != 8)
                || (doubleColonSplit.length == 2 && totalGroups > 7)) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address");
        }

        byte[] result = new byte[16];
        int groupIndex = 0;
        for (String part : headParts) {
            writeHextet(result, groupIndex++, part);
        }
        groupIndex += (8 - totalGroups);
        for (String part : tailParts) {
            writeHextet(result, groupIndex++, part);
        }

        if (trailingIpv4 != null) {
            System.arraycopy(trailingIpv4, 0, result, 12, 4);
        }
        return result;
    }

    private static byte[] parseIpv4Tail(String ipv4Tail) {
        String[] parts = ipv4Tail.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 embedded IPv4 address");
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            int val = parseDecimalOctet(parts[i]);
            if (val < 0 || val > 255) {
                throw new IllegalArgumentException("Invalid URL: malformed IPv6 embedded IPv4 address");
            }
            out[i] = (byte) val;
        }
        return out;
    }

    private static void writeHextet(byte[] target, int groupIndex, String hex) {
        if (hex.isEmpty() || hex.length() > 4) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address");
        }
        int value;
        try {
            value = Integer.parseInt(hex, 16);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address", ex);
        }
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("Invalid URL: malformed IPv6 address");
        }
        target[groupIndex * 2] = (byte) ((value >>> 8) & 0xFF);
        target[groupIndex * 2 + 1] = (byte) (value & 0xFF);
    }
}
