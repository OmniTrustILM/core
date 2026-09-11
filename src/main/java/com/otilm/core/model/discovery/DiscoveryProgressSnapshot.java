package com.otilm.core.model.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;

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
        return progress != null && (progress.getTargetsProcessed() != null || progress.getTargetsTotal() != null
                || progress.getTargetsFailed() != null || progress.getPhase() != null
                || progress.getByResource() != null);
    }
}
