package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.core.dao.entity.Discovery;

/**
 * The fence on what a tick writes for a checkpointed run. A tick remembers the checkpoint revision of the run it built
 * its request from; every applied page, stop and resume raises it, so a tick whose revision is no longer the run's was
 * overtaken and must not apply its page, spend the budget, end the run or reschedule its row. Buffered runs are never
 * fenced.
 */
final class CheckpointRevision {

    private CheckpointRevision() {
    }

    /** A drain tick's fence: the checkpointed run is still at the revision the tick read. */
    static DiscoveryTickFence fence(long revisionTheTickRead) {
        return lockedRun -> !movedOn(lockedRun, revisionTheTickRead);
    }

    /** Whether {@code run}, read under its row lock, is a checkpointed run that has moved past the tick's revision. */
    static boolean movedOn(Discovery run, long revisionTheTickRead) {
        return run.getDeliveryMode() == DiscoveryDeliveryMode.CHECKPOINTED
                && run.getCheckpointRevision() != revisionTheTickRead;
    }
}
