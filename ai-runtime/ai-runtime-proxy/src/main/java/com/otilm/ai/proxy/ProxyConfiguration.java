package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import org.apache.hc.core5.net.InetAddressUtils;

/** Immutable administrator configuration; none of these values is accepted in a local request. */
public record ProxyConfiguration(URI coreOrigin, InetAddress coreAddress, Path certificateFile, Path privateKeyFile,
        Path serverCaFile) {
    public ProxyConfiguration {
        try {
            new CoreEndpoint(coreOrigin, coreAddress);
        } catch (IllegalArgumentException invalidEndpoint) {
            throw invalid();
        }
        if (certificateFile == null || privateKeyFile == null || serverCaFile == null || !certificateFile.isAbsolute()
                || !privateKeyFile.isAbsolute() || !serverCaFile.isAbsolute()
                || certificateFile.normalize().getParent() == null || privateKeyFile.normalize().getParent() == null
                || serverCaFile.normalize().getParent() == null
                || !certificateFile.normalize().getParent().equals(privateKeyFile.normalize().getParent())) {
            throw invalid();
        }
        certificateFile = certificateFile.normalize();
        privateKeyFile = privateKeyFile.normalize();
        serverCaFile = serverCaFile.normalize();
    }

    public static ProxyConfiguration fromArguments(String[] arguments) {
        if (arguments == null || arguments.length != 5) {
            throw invalid();
        }
        try {
            String address = arguments[1];
            if (!InetAddressUtils.isIPv4(address) && !InetAddressUtils.isIPv6(address)) {
                throw invalid();
            }
            return new ProxyConfiguration(URI.create(arguments[0]), InetAddress.getByName(address),
                    Path.of(arguments[2]), Path.of(arguments[3]), Path.of(arguments[4]));
        } catch (Exception failure) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CONFIGURATION");
    }
}
