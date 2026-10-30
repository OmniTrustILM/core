package com.otilm.core.model.cbom;

import java.util.List;
import java.util.UUID;

/**
 * One source row's navigation refs, keyed by the asset it links: what the CBOM-scoped listing joins onto its page. A
 * projection rather than the entity, because the row's JSONB payload and evidence are not served by that listing and a
 * page can be 1000 rows.
 */
public record CryptoAssetSourceBomRefsRow(UUID assetUuid, List<String> bomRefs) {
}
