package com.otilm.ai.gateway;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLContext;

// Trusted transport configuration only. Construction neither approves a destination nor grants send authority.
record PinnedEndpoint(URI origin, List<InetAddress> addresses, SSLContext trust) {
    PinnedEndpoint {
        Objects.requireNonNull(origin);
        Objects.requireNonNull(trust);
        addresses = List.copyOf(addresses);
        if (!"https".equals(origin.getScheme()) || origin.getHost() == null || origin.getUserInfo() != null
                || origin.getRawQuery() != null || origin.getRawFragment() != null
                || (!origin.getRawPath().isEmpty() && !origin.getRawPath().equals("/")) || origin.getPort() < 1
                || origin.getPort() > 65535 || addresses.isEmpty()) {
            throw new GatewayFailure(GatewayFailure.Code.INVALID_REQUEST);
        }
    }
}
