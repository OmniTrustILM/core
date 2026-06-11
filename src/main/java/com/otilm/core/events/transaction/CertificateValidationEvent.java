package com.otilm.core.events.transaction;

import java.util.List;
import java.util.UUID;

public record CertificateValidationEvent(List<UUID> certificateUuids, UUID discoveryUuid, String discoveryName, UUID locationUuid, String locationName) {

    public CertificateValidationEvent(UUID certificateUuid) {
        this(List.of(certificateUuid), null, null, null, null);
    }

    public CertificateValidationEvent(List<UUID> certificateUuids) {
        this(certificateUuids, null, null, null, null);
    }
}
