package com.otilm.core.security.ai;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Finite trusted input for one synchronous certificate read. An empty set grants no objects. */
public record CertificateReadScope(UUID raProfileUuid, Set<UUID> certificateUuids) {
    public CertificateReadScope {
        Objects.requireNonNull(raProfileUuid, "RA profile is required");
        Objects.requireNonNull(certificateUuids, "Certificate scope is required");
        certificateUuids = Set.copyOf(certificateUuids);
        if (certificateUuids.size() > 100) {
            throw new IllegalArgumentException("Certificate scope exceeds the read limit");
        }
    }
}
