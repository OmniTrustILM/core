package com.otilm.core.security.ai;

import java.util.Objects;
import java.util.Optional;

/** Fixed workload caller roles; a parsed URI alone supplies no authentication or operation authority. */
public enum RuntimePeerRole {
    RUNNER_PROXY("ilm-runtime-proxy"),
    CONTROLLER("ilm-runtime-controller"),
    GATEWAY_RUN("ilm-runtime-gateway-run"),
    GATEWAY_MANAGEMENT("ilm-runtime-gateway-management");

    private final String scheme;

    RuntimePeerRole(String scheme) {
        this.scheme = scheme;
    }

    public Optional<RuntimePeer> parseCertificateUri(String encoded) {
        if (encoded == null || !encoded.startsWith(scheme + "://")) {
            return Optional.empty();
        }
        String runnerForm = "ilm-runtime-proxy" + encoded.substring(scheme.length());
        return RuntimeProxyCertificateClaims.parse(runnerForm).map(subject -> new RuntimePeer(this, subject));
    }

    public String certificateUri(RuntimeProxyCertificateClaims subject) {
        String uri = Objects.requireNonNull(subject).uri();
        return scheme + uri.substring(uri.indexOf(':'));
    }
}
