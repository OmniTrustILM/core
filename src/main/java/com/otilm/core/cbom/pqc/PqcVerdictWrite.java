package com.otilm.core.cbom.pqc;

import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import java.util.UUID;

/**
 * One row's verdict, ready for the batch writer.
 *
 * @param row the inputs and verdict history read together with the row's {@code xmin}
 * @param referenceBasis {@link PqcReferences#basis()} as read, for a certificate or protocol
 */
public record PqcVerdictWrite(PqcStaleVerdictRow row, PqcDecision decision, String referenceBasis) {

    public PqcVerdictWrite(PqcStaleVerdictRow row, PqcDecision decision) {
        this(row, decision, null);
    }

    public UUID assetUuid() {
        return row.uuid();
    }

    public long rowVersion() {
        return row.rowVersion();
    }
}
