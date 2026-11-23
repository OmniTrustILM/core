package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import java.util.Arrays;
import java.util.Objects;

/**
 * A certificate as the platform holds it.
 *
 * @param uuid the platform's identifier of the certificate
 * @param fingerprintSha256 SHA-256 fingerprint Core computed from {@code content}, the key it matches inventory
 * certificates by
 * @param content the certificate as the platform returned it
 * @param state the platform state
 * @param message why the state is what it is, shaped by Core; {@code null} when there is nothing to add
 */
public record PlatformRecord(String uuid, String fingerprintSha256, byte[] content,
        TrustedCertificatePlatformState state, String message) {

    // Overridden so the content is compared by value and kept out of logs.
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PlatformRecord that)) {
            return false;
        }
        return Objects.equals(uuid, that.uuid) && Objects.equals(fingerprintSha256, that.fingerprintSha256)
                && Arrays.equals(content, that.content) && state == that.state && Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(uuid, fingerprintSha256, state, message) + Arrays.hashCode(content);
    }

    @Override
    public String toString() {
        return "PlatformRecord[uuid=%s, fingerprintSha256=%s, state=%s, message=%s]"
                .formatted(uuid, fingerprintSha256, state, message);
    }
}
