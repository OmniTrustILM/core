package com.otilm.core.events.handlers.discovery;

import java.util.UUID;

/**
 * The verdict for one discovered-certificate row.
 *
 * @param detail the shaped reason, safe to expose — {@code processedError} is returned to API clients, so this must
 * never carry a raw exception message. {@code null} on a clean outcome.
 */
public record DiscoveryCertificateResult(UUID discoveryCertificateUuid, DiscoveryCertificateOutcome outcome,
        String detail) {
}
