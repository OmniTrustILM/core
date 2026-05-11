package com.czertainly.core.util.serialnumber;

import java.net.*;
import java.util.ArrayList;
import java.util.function.Supplier;

/**
 * Resolves the instance ID used by {@link SnowflakeSerialNumberGenerator} to distinguish replicas.
 *
 * <h2>Resolution order</h2>
 * <ol>
 *   <li>{@code ILM_INSTANCE_ID} environment variable — explicit override, range {@code 0–65535}.</li>
 *   <li>Auto-derived from the last two octets (lower 16 bits) of the container's private IPv4 address.</li>
 * </ol>
 *
 * Auto-derivation is safe when all instances have IP addresses whose <b>last two octets are unique</b>
 * (e.g. pod CIDR ≤ /16, Docker bridge/overlay ≤ /16, or all VMs within a single /16 subnet).
 * It silently collides — and must not be used — in the following cases:
 *
 * <pre>
 * | Scenario                              | Risk                                                        |
 * |---------------------------------------|-------------------------------------------------------------|
 * | Multiple processes on the same host   | All share the same IP → same ID                             |
 * | Docker with --network host            | All containers share the host IP → same ID                  |
 * | Network CIDR wider than /16           | Instances in different /16 sub-ranges share the same last   |
 * |                                       | two octets (e.g. 10.1.1.5 and 10.2.1.5 both yield ID 261)  |
 * | Multiple clusters sharing a CA        | Pods from separate /16 networks can share the same last two |
 * |                                       | octets even if each cluster is individually collision-free   |
 * </pre>
 *
 * At startup, the resolved prefix length of the selected interface is checked: a prefix wider than /16
 * triggers a warning. Cross-cluster collisions cannot be detected at runtime.
 * Set {@code ILM_INSTANCE_ID} explicitly whenever the above conditions apply.
 */
final class InstanceIdResolver {

    static final String INSTANCE_ID_ENV_VAR = "ILM_INSTANCE_ID";

    private InstanceIdResolver() {
    }

    static Resolution resolve() {
        String envValue = System.getenv(INSTANCE_ID_ENV_VAR);
        if (envValue != null && !envValue.isBlank()) {
            int id = resolve(envValue, () -> null);
            return new Resolution(id, Source.ENV_VAR, (short) -1);
        }
        InetAddress address = findLocalAddress();
        int id = extractIdFromAddress(address.getAddress());
        short prefixLength = findPrefixLength(address);
        return new Resolution(id, Source.IP_ADDRESS, prefixLength);
    }

    private static InetAddress findLocalAddress() {
        try {
            InetAddress localAddress = InetAddress.getLocalHost();
            return isUsableAddress(localAddress) ? localAddress : findUsableAddress();
        } catch (UnknownHostException e) {
            return findUsableAddress();
        }
    }

    private static InetAddress findUsableAddress() {
        try {
            var interfaces = NetworkInterface.getNetworkInterfaces();
            var usable = new ArrayList<InetAddress>();
            while (interfaces.hasMoreElements()) {
                var ni = interfaces.nextElement();
                var addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    var addr = addresses.nextElement();
                    if (isUsableAddress(addr)) {
                        usable.add(addr);
                    }
                }
            }
            if (usable.isEmpty()) {
                throw new IllegalStateException(
                        "No suitable network address found for instance ID. Set " + INSTANCE_ID_ENV_VAR + " explicitly.");
            }
            return usable.stream()
                    .filter(Inet4Address.class::isInstance)
                    .findFirst()
                    .orElse(usable.getFirst());
        } catch (SocketException e) {
            throw new IllegalStateException(
                    "No suitable network address found for instance ID. Set " + INSTANCE_ID_ENV_VAR + " explicitly.", e);
        }
    }

    static boolean isUsableAddress(InetAddress addr) {
        return !addr.isLoopbackAddress()
                && !addr.isLinkLocalAddress()
                && !addr.isMulticastAddress()
                && !addr.isAnyLocalAddress();
    }

    static int resolve(String envValue, Supplier<InetAddress> addressSupplier) {
        if (envValue != null && !envValue.isBlank()) {
            int id;
            try {
                id = Integer.parseInt(envValue.strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        INSTANCE_ID_ENV_VAR + " must be a valid integer, got: '" + envValue.strip() + "'");
            }
            if (id < 0 || id > 65535) {
                throw new IllegalArgumentException(
                        INSTANCE_ID_ENV_VAR + " must be between 0 and 65535, got: " + id);
            }
            return id;
        }

        byte[] address = addressSupplier.get().getAddress();
        return extractIdFromAddress(address);
    }

    static int extractIdFromAddress(byte[] address) {
        // IPv6 address
        if (address.length == 16) {
            // XOR-fold the last 4 bytes into 16 bits. Unlike simple truncation, XOR-folding
            // preserves entropy from both halves of the input. We use only the last 4 bytes
            // because the IPv6 prefix (first 8-12 bytes) is shared across hosts on the same
            // network and adds no distinguishing value.
            int hi = ((address[12] & 0xFF) << 8) | (address[13] & 0xFF);
            int lo = ((address[14] & 0xFF) << 8) | (address[15] & 0xFF);
            return (hi ^ lo) & 0xFFFF;
        }
        // IPv4 address
        return ((address[address.length - 2] & 0xFF) << 8) | (address[address.length - 1] & 0xFF);
    }

    static short findPrefixLength(InetAddress address) {
        try {
            NetworkInterface ni = NetworkInterface.getByInetAddress(address);
            if (ni != null) {
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    if (ia.getAddress().equals(address)) {
                        return ia.getNetworkPrefixLength();
                    }
                }
            }
        } catch (SocketException e) {
            // prefix length is best-effort
        }
        return -1;
    }

    enum Source {ENV_VAR, IP_ADDRESS}

    record Resolution(int id, Source source, short prefixLength) {
    }
}
