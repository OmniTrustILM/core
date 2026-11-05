package com.otilm.core.model.crypto;

import java.util.UUID;

/** The token profile and token that scope a v2 operation on a key. */
public record KeyOperationScope(UUID tokenProfileUuid, UUID tokenInstanceReferenceUuid) {
}
