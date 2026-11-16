package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.core.dao.entity.Discovery;

/**
 * The fence on what a tick writes for a checkpointed run. A tick remembers the checkpoint revision of the run it built
 * its request from. Every applied page, stop and resume raises it, so a tick whose revision is no longer the run's was
 * overtaken and must not apply its page, spend the budget, end the run or reschedule its row.
 */
final class CheckpointRevision {

    private CheckpointRevision() {
    }

    /**
     * A drain tick's fence: the run is still at the revision the tick read. It holds a tick that read a checkpointed
     * run even once a resume has made the run buffered, so nothing built for the old mode lands after it.
     */
    static DiscoveryTickFence fence(long revisionTheTickRead, DiscoveryDeliveryMode modeTheTickRead) {
        return lockedRun -> !movedOn(lockedRun, revisionTheTickRead, modeTheTickRead);
    }

    /**
     * Whether {@code run}, read under its row lock, has moved past the revision a tick read: either the run as the tick
     * read it or the run as it is now is checkpointed, and the revision differs.
     */
    static boolean movedOn(Discovery run, long revisionTheTickRead, DiscoveryDeliveryMode modeTheTickRead) {
        return (isCheckpointed(modeTheTickRead) || isCheckpointed(run.getDeliveryMode()))
                && run.getCheckpointRevision() != revisionTheTickRead;
    }

    private static boolean isCheckpointed(DiscoveryDeliveryMode mode) {
        return mode == DiscoveryDeliveryMode.CHECKPOINTED;
    }
}
