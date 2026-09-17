package com.otilm.core.model.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * What Core will accept as a progress report from a connector.
 */
public final class DiscoveryProgressSnapshot {

    private DiscoveryProgressSnapshot() {
    }

    /**
     * Whether a reported snapshot is worth keeping. An all-null one says what omitting the field says — nothing to
     * report — so storing it would replace what the run already knows with blanks. Connector responses are not
     * bean-validated, so the contract's "omit rather than send an empty object" cannot be enforced on arrival, and both
     * the polled status and the pushed progress event arrive through it.
     */
    public static boolean reportsSomething(DiscoveryProgressDto progress) {
        // updatedAt is deliberately not part of this test: Core sets it, so a snapshot carrying only that one still
        // reports nothing.
        return progress != null && (progress.getTargetsProcessed() != null || progress.getTargetsTotal() != null
                || progress.getTargetsFailed() != null || progress.getPhase() != null
                || progress.getByResource() != null);
    }

    /**
     * Stamps a snapshot with the moment it was recorded, replacing anything a connector sent in that field. Both write
     * paths go through here so the timestamp cannot be left behind by one of them, and so it always means Core's clock
     * rather than the connector's.
     *
     * @return the same instance, for use in place
     */
    public static DiscoveryProgressDto recorded(DiscoveryProgressDto progress) {
        progress.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return progress;
    }
}
