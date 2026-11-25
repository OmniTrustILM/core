package com.otilm.core.service.renewal.refresh;

import java.util.List;
import java.util.UUID;

/** Certificates of one RA profile whose renewal information is asked for in one connector request. */
public record RefreshBatch(UUID raProfileUuid, List<UUID> certificateUuids) {
}
