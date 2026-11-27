package com.otilm.core.signing;

import java.util.UUID;

/**
 * A Signing Profile holding a certificate, either through its current version or only through superseded ones.
 */
public record CertificateHold(UUID certificateUuid, String signingProfileName, boolean currentVersion) {
}
