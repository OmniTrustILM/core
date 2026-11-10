package com.otilm.core.service.handler.discovery;

/** What applying one drained page did to its run. */
public enum DrainPageOutcome {

    /** Items were staged, or a checkpointed run's position moved. */
    ADVANCED,

    /** Nothing new: no item past the cursor, and for a checkpointed run the same position again. */
    NOT_ADVANCED,

    /**
     * A checkpointed page built from a position the run has since left, dropped without writing anything. Another tick,
     * a stop or a resume moved the run on, and whoever did has already scheduled what comes next.
     */
    STALE
}
