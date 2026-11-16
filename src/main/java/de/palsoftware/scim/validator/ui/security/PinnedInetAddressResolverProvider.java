package de.palsoftware.scim.validator.ui.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

/**
 * Minimal bootstrap JDK {@link InetAddressResolverProvider} that avoids loading third-party HTTP
 * libraries during early JVM {@link InetAddress} initialization (such as Java agent startup) and
 * delegates to {@link PinnedTargetHttpSupport} once ready while preserving standard JVM DNS caching
 * for non-pinned infrastructure hosts.
 */
public final class PinnedInetAddressResolverProvider extends InetAddressResolverProvider {

    @FunctionalInterface
    interface ResolverHook {
        Stream<InetAddress> lookup(
                String host,
                InetAddressResolver.LookupPolicy lookupPolicy,
                InetAddressResolver builtin) throws UnknownHostException;
    }

    static final AtomicReference<InetAddressResolver> BUILTIN_RESOLVER = new AtomicReference<>();
    static final AtomicReference<ResolverHook> RESOLVER_HOOK = new AtomicReference<>();

    @Override
    public InetAddressResolver get(Configuration builtinConfiguration) {
        InetAddressResolver builtin = builtinConfiguration.builtinResolver();
        BUILTIN_RESOLVER.set(builtin);
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
                    throws UnknownHostException {
                ResolverHook hook = RESOLVER_HOOK.get();
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
