package com.otilm.core.cbom.pqc;

import java.util.UUID;

/**
 * One row's verdict, ready for the batch writer.
 *
 * @param rowVersion the row's {@code xmin} when its inputs were read; the write is refused if another transaction has
 * written the row since
 * @param referenceBasis {@link PqcReferences#basis()} as read, for a certificate or protocol
 */
public record PqcVerdictWrite(UUID assetUuid, long rowVersion, PqcDecision decision, String referenceBasis) {

    public PqcVerdictWrite(UUID assetUuid, long rowVersion, PqcDecision decision) {
        this(assetUuid, rowVersion, decision, null);
    }
}
