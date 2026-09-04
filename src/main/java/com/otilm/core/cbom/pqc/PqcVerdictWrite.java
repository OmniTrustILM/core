package com.otilm.core.cbom.pqc;

import java.util.UUID;

/** One row's verdict, ready for the batch writer. */
public record PqcVerdictWrite(UUID assetUuid, PqcDecision decision) {
}
