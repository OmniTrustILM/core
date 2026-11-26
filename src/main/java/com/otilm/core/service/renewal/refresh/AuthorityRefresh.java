package com.otilm.core.service.renewal.refresh;

import java.util.List;
import java.util.UUID;

/** The batches claimed for one authority, asked for one after another. */
public record AuthorityRefresh(UUID authorityUuid, List<RefreshBatch> batches) {

    public int certificateCount() {
        return batches.stream().mapToInt(batch -> batch.certificateUuids().size()).sum();
    }
}
