package com.otilm.core.model.cbom;

/** What one row of a CBOM's ingest report says. */
public enum CbomIngestFindingKind {
    /** Something the pipeline had to tell the producer: a dropped value, a withheld digest, an ambiguous reference. */
    FINDING,
    /** A component that yielded no asset at all, named with the failure class rather than with its payload. */
    SKIP
}
