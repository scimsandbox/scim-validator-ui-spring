package de.palsoftware.scim.validator.ui.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.security.Security;
import java.util.stream.Stream;

/**
 * Minimal bootstrap JDK {@link InetAddressResolverProvider} that disables JVM DNS result caching
 * before {@code InetAddressCachePolicy} initializes, avoids loading third-party HTTP libraries during
 * early JVM {@link InetAddress} bootstrap, and delegates to {@link PinnedTargetHttpSupport} once ready.
 */
public final class PinnedInetAddressResolverProvider extends InetAddressResolverProvider {

    static {
        Security.setProperty("networkaddress.cache.ttl", "0");
        Security.setProperty("networkaddress.cache.negative.ttl", "0");
    }

    @FunctionalInterface
    interface ResolverHook {
        Stream<InetAddress> lookup(
                String host,
                InetAddressResolver.LookupPolicy lookupPolicy,
                InetAddressResolver builtin) throws UnknownHostException;
    }

    static volatile InetAddressResolver builtinResolver;
    static volatile ResolverHook resolverHook;

    @Override
    public InetAddressResolver get(Configuration builtinConfiguration) {
        InetAddressResolver builtin = builtinConfiguration.builtinResolver();
        builtinResolver = builtin;
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
                    throws UnknownHostException {
                ResolverHook hook = resolverHook;
                return hook != null
                        ? hook.lookup(host, lookupPolicy, builtin)
                        : builtin.lookupByName(host, lookupPolicy);
            }

            @Override
            public String lookupByAddress(byte[] addr) throws UnknownHostException {
                return builtin.lookupByAddress(addr);
            }
        };
    }

    @Override
    public String name() {
        return "scim-validator-pinned-dns-resolver";
    }
}
