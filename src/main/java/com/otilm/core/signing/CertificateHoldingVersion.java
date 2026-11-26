package com.otilm.core.signing;

import java.util.UUID;

/**
 * A stored Signing Profile version that holds a certificate, with the version number its profile is currently at.
 */
public record CertificateHoldingVersion(UUID certificateUuid, String signingProfileName, int version,
        int currentVersion) {

    public boolean isCurrent() {
        return version == currentVersion;
    }
}
