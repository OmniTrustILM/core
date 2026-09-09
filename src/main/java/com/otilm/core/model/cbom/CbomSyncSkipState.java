package com.otilm.core.model.cbom;

/** Where a feed entry that Core could not store stands in its bounded retry. */
public enum CbomSyncSkipState {
    /** Retried at the end of each sync run until the attempt budget is spent. */
    RETRYING,
    /** The budget is spent; the entry is kept as a record and never retried by the sync. */
    PERMANENTLY_SKIPPED
}
