package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CbomSyncedEventData;
import com.otilm.api.model.common.events.data.CryptoAssetAddedEventData;
import java.util.List;

/** Values captured after the CBOM's asset ingest and superseded-source withdrawal settle. */
public record CbomSyncedEventPayload(CbomSyncedEventData cbom, List<CryptoAssetAddedEventData> assets) {
}
