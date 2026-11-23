package com.otilm.core.security.ai;

import java.util.Objects;

/** Role-preserving certificate identity; current registered workload and business checks remain required. */
public record RuntimePeer(RuntimePeerRole role, RuntimeProxyCertificateClaims subject) {
    public RuntimePeer {
        Objects.requireNonNull(role);
        Objects.requireNonNull(subject);
    }

    public String certificateUri() {
        return role.certificateUri(subject);
    }

    @Override
    public String toString() {
        return "RuntimePeer[role=" + role + "]";
    }
}
