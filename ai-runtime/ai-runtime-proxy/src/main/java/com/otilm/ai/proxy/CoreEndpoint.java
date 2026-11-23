package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;

/** Administrator fixed Core destination; construction grants no identity or operation authority. */
public record CoreEndpoint(URI origin, InetAddress address) {
    public CoreEndpoint {
        if (origin == null || address == null || !"https".equals(origin.getScheme()) || origin.getHost() == null
                || origin.getRawUserInfo() != null || origin.getRawQuery() != null || origin.getRawFragment() != null
                || (origin.getRawPath().length() > 128 || !origin.getRawPath().matches("(?:/[A-Za-z0-9_-]++)*+"))
                || origin.getPort() == 0 || origin.getPort() > 65535 || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            throw new IllegalArgumentException("CORE_ENDPOINT");
        }
    }
}
