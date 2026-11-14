package de.palsoftware.scim.validator.ui.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TargetUrlPolicyTest {

    private static TargetUrlPolicy.HostAddressResolver fixedResolver(String... ips) {
        return host -> {
            if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)) {
                return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
            }
            if ("::1".equals(host)) {
                return new InetAddress[]{InetAddress.getByName("::1")};
            }
            InetAddress[] resolved = new InetAddress[ips.length];
            for (int i = 0; i < ips.length; i++) {
                resolved[i] = InetAddress.getByName(ips[i]);
            }
            return resolved;
        };
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://scim.example.com/scim/v2",
            "https://scim.example.com:8443/scim/v2/Users",
            "https://scim.example.com:9090/scim/v2",
            "HTTPS://SCIM.EXAMPLE.COM/scim/v2"
    })
    void httpsPublicTargetsAreAllowedWhenResolvingToPublicIpsIncludingPort9090(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                false,
                fixedResolver("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"));

        assertThat(policy.validateUri(url)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:8080/scim/v2",
            "http://127.0.0.1:8080/scim/v2",
            "https://localhost:8443/scim/v2",
            "https://api.localhost:8443/scim/v2",
            "https://127.0.0.1:8443/scim/v2",
            "https://[::1]:8443/scim/v2"
    })
    void localhostTargetsAreRejectedByDefault(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> policy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:8080/scim/v2",
            "http://127.0.0.1:8080/scim/v2",
            "http://LOCALHOST:8080/scim/v2",
            "http://[::1]:8080/scim/v2",
            "https://localhost:8443/scim/v2"
    })
    void localhostTargetsAreAllowedOnlyWhenExplicitlyEnabled(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(true, fixedResolver("93.184.216.34"));

        assertThat(policy.validateUri(url)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost:9090/actuator/prometheus",
            "http://127.0.0.1:9090/scim/v2",
            "http://[::1]:9090/scim/v2",
            "https://[::ffff:127.0.0.1]:9090/scim/v2"
    })
    void managementPortIsBlockedOnLoopbackTargetsEvenWhenLocalhostAllowed(String url) {
        TargetUrlPolicy strictPolicy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));
        TargetUrlPolicy localPolicy = new TargetUrlPolicy(true, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> strictPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("9090");
        assertThatThrownBy(() -> localPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("9090");
    }

    @Test
    void customManagementPortAndHostnameResolvingToLoopbackOnManagementPortAreHandledProperly() {
        TargetUrlPolicy customPortPolicy = new TargetUrlPolicy(true, 19090, fixedResolver("93.184.216.34"));
        assertThat(customPortPolicy.getManagementPort()).isEqualTo(19090);
        assertThat(customPortPolicy.validateUri("http://localhost:9090/scim/v2")).isNotNull();
        assertThatThrownBy(() -> customPortPolicy.validateUri("http://localhost:19090/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("19090");

        TargetUrlPolicy rebindToLoopbackMgmtPort = new TargetUrlPolicy(
                false, 9090, host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")});
        assertThatThrownBy(() -> rebindToLoopbackMgmtPort.validateUri("https://scim.example.com:9090/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("9090");

        TargetUrlPolicy disabledMgmtPortPolicy = new TargetUrlPolicy(true, 0, fixedResolver("93.184.216.34"));
        assertThat(disabledMgmtPortPolicy.validateUri("http://localhost:9090/scim/v2")).isNotNull();

        TargetUrlPolicy twoArgAutowiredCtor = new TargetUrlPolicy(false, 9090);
        assertThat(twoArgAutowiredCtor.isAllowLocalhostTargets()).isFalse();
        assertThat(twoArgAutowiredCtor.getManagementPort()).isEqualTo(9090);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://scim.example.com/scim/v2",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/scim/v2"
    })
    void plainHttpNonLocalhostIsAlwaysRejected(String url) {
        TargetUrlPolicy strictPolicy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));
        TargetUrlPolicy localPolicy = new TargetUrlPolicy(true, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> strictPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
        assertThatThrownBy(() -> localPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("only allowed for localhost");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://printer.local/scim/v2",
            "https://vault.internal/scim/v2",
            "https://scim.default.svc/scim/v2",
            "https://scim.default.svc.cluster.local/scim/v2",
            "https://intranet/scim/v2",
            "https://local/scim/v2"
    })
    void internalClusterMetadataAndSingleLabelHostnamesAreRejected(String url) {
        TargetUrlPolicy strictPolicy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));
        TargetUrlPolicy localPolicy = new TargetUrlPolicy(true, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> strictPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> localPolicy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1",
            "127.0.53.53",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.10",
            "169.254.169.254",
            "169.254.170.2",
            "100.64.0.1",
            "100.127.255.254",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "ff02::1",
            "64:ff9b::a00:1"
    })
    void dnsResolutionToPrivateLoopbackMetadataCgnatOrReservedAddressesIsRejected(String resolvedIp) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver(resolvedIp));

        assertThatThrownBy(() -> policy.validateUri("https://scim.attacker.example/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("target addresses are not allowed");
    }

    @Test
    void localhostResolvingToNonLoopbackIsRejectedEvenWhenLocalhostAllowed() {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                true,
                host -> new InetAddress[]{InetAddress.getByName("93.184.216.34")});

        assertThatThrownBy(() -> policy.validateUri("http://localhost:8080/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-loopback");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "172.15.255.254",
            "172.32.0.1",
            "100.63.255.254",
            "100.128.0.1",
            "93.184.216.34"
    })
    void publicIpsJustOutsidePrivateAndCgnatBoundariesAreAllowed(String publicIp) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver(publicIp));

        assertThat(policy.validateUri("https://scim.example.com/scim/v2")).isNotNull();
    }

    @Test
    void multiRecordDnsContainingAnyPrivateIpIsRejected() {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34", "10.0.0.5"));

        assertThatThrownBy(() -> policy.validateUri("https://dual-homed.example.com/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("target addresses are not allowed");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://[::ffff:127.0.0.1]/scim/v2",
            "https://[::ffff:169.254.169.254]/scim/v2",
            "https://2130706433/scim/v2",
            "https://0x7f000001/scim/v2",
            "https://0177.0.0.1/scim/v2",
            "https://scim.0x10/scim/v2",
            "https://user:secret@scim.example.com/scim/v2",
            "https://[fe80::1%25eth0]/scim/v2",
            "https://[2001:::1]/scim/v2",
            "https://[not-an-ipv6]/scim/v2"
    })
    void privateIpv4MappedIpv6AlternateNumericEncodingsUserInfoZoneIdsAndMalformedIpv6AreRejected(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(true, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> policy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void publicIpv4MappedIpv6LiteralIsAllowedWhenHttps() throws Exception {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                false,
                host -> new InetAddress[]{InetAddress.getByName(host)});

        TargetUrlPolicy.ResolvedTarget resolved = policy.resolve("https://[::ffff:93.184.216.34]/scim/v2");
        assertThat(resolved.uri()).isNotNull();
        assertThat(resolved.addresses()).containsExactly(InetAddress.getByName("93.184.216.34"));
    }

    @Test
    void unresolvableHostnameThrowsIllegalArgumentException() {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, host -> {
            throw new UnknownHostException(host);
        });

        assertThatThrownBy(() -> policy.validateUri("https://nonexistent.example.test/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("could not be resolved");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ftp://example.com/x", "file:///etc/passwd", "gopher://example.com"})
    void nonHttpSchemesAreRejected(String url) {
        assertThatThrownBy(() -> TargetUrlPolicy.DEFAULT_STRICT.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("only http and https");
    }

    @Test
    void blankTargetIsRejected() {
        assertThatThrownBy(() -> TargetUrlPolicy.DEFAULT_STRICT.validateUri("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void targetWithoutHostIsRejected() {
        assertThatThrownBy(() -> TargetUrlPolicy.DEFAULT_STRICT.validateUri("https:///scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must include a host");
    }

    @Test
    void isAllowLocalhostTargetsReflectsConfiguration() {
        assertThat(new TargetUrlPolicy(false, fixedResolver("93.184.216.34")).isAllowLocalhostTargets()).isFalse();
        assertThat(new TargetUrlPolicy(true, fixedResolver("93.184.216.34")).isAllowLocalhostTargets()).isTrue();
    }

    @Test
    void defaultStrictAllowsPublicIpLiteralWithoutExternalDns() {
        assertThat(TargetUrlPolicy.DEFAULT_STRICT.validateUri("https://93.184.216.34/scim/v2")).isNotNull();
        assertThatThrownBy(() -> TargetUrlPolicy.DEFAULT_STRICT.validateUri(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://exa mple.com/scim/v2",
            "://example.com/scim/v2",
            "https://scim.example.com:0/scim/v2",
            "https://scim.example.com:70000/scim/v2",
            "https://.../scim/v2"
    })
    void malformedUriSchemePortAndDotOnlyHostsAreRejected(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> policy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void trailingDotsOnPublicHostnameAreNormalizedAndAllowed() {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));

        TargetUrlPolicy.ResolvedTarget resolved = policy.resolve("https://SCIM.EXAMPLE.COM./scim/v2");
        assertThat(resolved.host()).isEqualTo("scim.example.com");
    }

    @Test
    void subdomainOfLocalhostIsRejectedEvenWhenAllowLocalhostTargetsTrue() {
        TargetUrlPolicy localPolicy = new TargetUrlPolicy(true, fixedResolver("127.0.0.1"));

        assertThatThrownBy(() -> localPolicy.validateUri("https://api.localhost/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("localhost targets are not allowed");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://93.184.216.34/scim/v2",
            "https://[2606:2800:220:1:248:1893:25c8:1946]/scim/v2",
            "https://[2606:2800::1]/scim/v2",
            "https://[2606:2800::]/scim/v2"
    })
    void canonicalPublicIpv4AndIpv6LiteralsAreAllowed(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                false,
                host -> new InetAddress[]{InetAddress.getByName(host)});

        assertThat(policy.validateUri(url)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://1.2..4/scim/v2",
            "https://1234.1.2.3/scim/v2",
            "https://256.1.2.3/scim/v2",
            "https://[::]/scim/v2",
            "https://[::0.0.0.2]/scim/v2"
    })
    void malformedNumericAndUnspecifiedOrIpv4CompatibleLiteralsAreRejected(String url) {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                false,
                fixedResolver("93.184.216.34"));

        assertThatThrownBy(() -> policy.validateUri(url))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fourLabelAlphaHostnameIsNotTreatedAsIpv4LiteralAndIsAllowed() {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver("93.184.216.34"));

        assertThat(policy.validateUri("https://a.b.c.example/scim/v2")).isNotNull();
    }

    @Test
    void resolverReturningNullEmptyOrNullElementIsRejected() {
        TargetUrlPolicy nullArrayPolicy = new TargetUrlPolicy(false, host -> null);
        TargetUrlPolicy emptyArrayPolicy = new TargetUrlPolicy(false, host -> new InetAddress[0]);
        TargetUrlPolicy nullElemPolicy = new TargetUrlPolicy(false, host -> new InetAddress[]{null});

        assertThatThrownBy(() -> nullArrayPolicy.validateUri("https://scim.example.com/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no addresses");
        assertThatThrownBy(() -> emptyArrayPolicy.validateUri("https://scim.example.com/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no addresses");
        assertThatThrownBy(() -> nullElemPolicy.validateUri("https://scim.example.com/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid resolved address");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "192.0.0.1",
            "198.18.0.1",
            "198.19.255.254",
            "fec0::1"
    })
    void reservedBenchmarkIetfProtocolAndSiteLocalIpv6AddressesAreRejected(String resolvedIp) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver(resolvedIp));

        assertThatThrownBy(() -> policy.validateUri("https://scim.example.com/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "192.0.1.1",
            "192.1.0.1",
            "198.17.255.254",
            "198.20.0.1",
            "fe00::1",
            "64:ff9a::1",
            "64:fe9b::1",
            "65:ff9b::1"
    })
    void nonReservedNeighboringIpv4AndIpv6RangesAreAllowed(String publicIp) {
        TargetUrlPolicy policy = new TargetUrlPolicy(false, fixedResolver(publicIp));

        assertThat(policy.validateUri("https://scim.example.com/scim/v2")).isNotNull();
    }

    @Test
    void localhostResolvingToNonLoopbackIpv6IsRejectedWhenLocalhostAllowed() {
        TargetUrlPolicy policy = new TargetUrlPolicy(
                true,
                host -> new InetAddress[]{InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946")});

        assertThatThrownBy(() -> policy.validateUri("http://localhost:8080/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-loopback");
    }

    @Test
    void ipLiteralsBypassDnsResolverAndIpv6FormsAreCanonicalizedAcrossResolveAndSameOrigin() {
        TargetUrlPolicy.HostAddressResolver failIfCalled = host -> {
            throw new AssertionError("DNS resolver must not be invoked for IP literal: " + host);
        };
        TargetUrlPolicy strictNoDnsPolicy = new TargetUrlPolicy(false, failIfCalled);
        TargetUrlPolicy localNoDnsPolicy = new TargetUrlPolicy(true, failIfCalled);

        TargetUrlPolicy.ResolvedTarget publicV4 = strictNoDnsPolicy.resolve("https://93.184.216.34/scim/v2");
        assertThat(publicV4.host()).isEqualTo("93.184.216.34");
        assertThat(strictNoDnsPolicy.validateSameOriginUri(publicV4, "https://93.184.216.34:443/scim/v2/Users"))
                .isNotNull();

        TargetUrlPolicy.ResolvedTarget publicV6 = strictNoDnsPolicy.resolve("https://[2606:2800:0220:0001::1]/scim/v2");
        assertThat(strictNoDnsPolicy.validateSameOriginUri(publicV6, "https://[2606:2800:220:1::1]/scim/v2/Users"))
                .isNotNull();
        assertThatThrownBy(() -> strictNoDnsPolicy.validateSameOriginUri(publicV6, "https://[not-ipv6]/scim/v2/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid URL");
        assertThatThrownBy(() -> TargetUrlPolicy.parseIpv6Literal("not-ipv6"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("malformed IPv6");

        assertThat(strictNoDnsPolicy.resolve("https://[::ffff:93.184.216.34]/scim/v2").host())
                .isEqualTo("93.184.216.34");

        // Expanded IPv6 loopback [0:0:0:0:0:0:0:1] behaves identically to [::1]
        assertThatThrownBy(() -> strictNoDnsPolicy.resolve("http://[0:0:0:0:0:0:0:1]:8080/scim/v2"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("localhost targets are not allowed");
        assertThatThrownBy(() -> localNoDnsPolicy.resolve("http://[0:0:0:0:0:0:0:1]:9090/actuator"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("9090");

        TargetUrlPolicy.ResolvedTarget loopV6 = localNoDnsPolicy.resolve("http://[::1]:8080/scim/v2");
        assertThat(localNoDnsPolicy.validateSameOriginUri(loopV6, "http://[0:0:0:0:0:0:0:1]:8080/scim/v2/Users"))
                .isNotNull();
        assertThat(localNoDnsPolicy.resolve("http://127.0.0.1:8080/scim/v2").host()).isEqualTo("127.0.0.1");
    }

    @Test
    void validateSyntaxAndValidateSameOriginUriPerformZeroDnsLookupsAndResolvedTargetIsImmutable() throws Exception {
        AtomicInteger dnsCalls = new AtomicInteger(0);
        TargetUrlPolicy policy = new TargetUrlPolicy(false, host -> {
            dnsCalls.incrementAndGet();
            return new InetAddress[]{InetAddress.getByName("93.184.216.34")};
        });

        assertThat(policy.validateSyntax("https://scim.example.com/scim/v2")).isNotNull();
        assertThat(dnsCalls.get()).isZero();

        TargetUrlPolicy.ResolvedTarget resolved = policy.resolve("https://scim.example.com/scim/v2");
        assertThat(dnsCalls.get()).isEqualTo(1);
        assertThat(resolved.host()).isEqualTo("scim.example.com");
        assertThatThrownBy(() -> resolved.addresses().clear())
                .isInstanceOf(UnsupportedOperationException.class);

        URI sameOriginExplicitPort = policy.validateSameOriginUri(
                resolved, "https://SCIM.EXAMPLE.COM.:443/scim/v2/Users?count=10");
        assertThat(sameOriginExplicitPort.getPath()).isEqualTo("/scim/v2/Users");
        assertThat(dnsCalls.get()).isEqualTo(1);

        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "https://user:pw@scim.example.com/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userinfo");
        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "https://[fe80::1%25eth0]/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("zone identifiers");
        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "http://scim.example.com/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("configured target origin");
        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "https://other.example.com/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("configured target origin");
        assertThatThrownBy(() -> policy.validateSameOriginUri(resolved, "https://scim.example.com:8443/Users"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("configured target origin");
        assertThat(dnsCalls.get()).isEqualTo(1);

        assertThatThrownBy(() -> new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com"), "  ", List.of(InetAddress.getByName("93.184.216.34"))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TargetUrlPolicy.ResolvedTarget(
                URI.create("https://scim.example.com"), "scim.example.com", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
