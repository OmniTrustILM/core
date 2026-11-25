package com.otilm.core.service.renewal.auto;

import java.time.Instant;
import java.util.UUID;

/**
 * What a handler needs to renew a certificate: the acting owner, the attempt limit, the time of the firing, and the
 * firing's trigger history and execution, either of which may be null.
 */
public record RenewalContext(UUID ownerUuid, int maxAttempts, Instant now, UUID triggerHistoryUuid,
        UUID executionUuid) {
}
