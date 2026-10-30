package com.otilm.core.events.handlers.discovery;

import java.security.PublicKey;
import java.util.List;
import java.util.UUID;

/**
 * One public key awaiting association, carried out of the import transaction so the orchestrator can merge it only if
 * that transaction committed. A rolled-back group therefore never contributes a key, which is what keeps an inventory
 * gap and a key gap from being counted for the same certificate.
 *
 * @param discoveryCertificateUuids the rows to mark should the association fail — the certificate-to-row mapping the
 * shared key map could not supply
 * @param unparseableReason non-null when the key could not be decoded at all, so a failure to even build the entry
 * surfaces as a key-association failure rather than only a log line
 */
public record KeyQueueEntry(PublicKey publicKey, boolean alternative, UUID certificateUuid,
        List<UUID> discoveryCertificateUuids, String unparseableReason) {

    public static KeyQueueEntry of(PublicKey publicKey, boolean alternative, UUID certificateUuid,
            List<UUID> discoveryCertificateUuids) {
        return new KeyQueueEntry(publicKey, alternative, certificateUuid, discoveryCertificateUuids, null);
    }

    public static KeyQueueEntry unparseable(boolean alternative, UUID certificateUuid,
            List<UUID> discoveryCertificateUuids, String reason) {
        return new KeyQueueEntry(null, alternative, certificateUuid, discoveryCertificateUuids, reason);
    }

    public boolean isUnparseable() {
        return unparseableReason != null;
    }
}
