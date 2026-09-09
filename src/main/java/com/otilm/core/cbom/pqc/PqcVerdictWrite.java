package com.otilm.core.cbom.pqc;

import java.util.UUID;

/**
 * One row's verdict, ready for the batch writer.
 *
 * @param rowVersion the row's {@code xmin} when its inputs were read; the write is refused if another transaction has
 * written the row since
 */
public record PqcVerdictWrite(UUID assetUuid, long rowVersion, PqcDecision decision) {
}
