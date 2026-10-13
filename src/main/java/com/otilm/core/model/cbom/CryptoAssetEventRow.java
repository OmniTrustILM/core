package com.otilm.core.model.cbom;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import jakarta.persistence.Tuple;
import java.util.UUID;

/** Event snapshot fields and the freshness of the verdict's elected-reference graph from one statement. */
public record CryptoAssetEventRow(UUID uuid, CryptographicAssetType assetType, String name, String algorithmFamily,
        PqcVerdict pqcVerdict, boolean currentVerdict) {

    public static CryptoAssetEventRow fromEventRow(Tuple row) {
        String verdict = row.get("pqc_verdict", String.class);
        return new CryptoAssetEventRow(row.get("uuid", UUID.class),
                CryptographicAssetType.valueOf(row.get("asset_type", String.class)), row.get("name", String.class),
                row.get("algorithm_family", String.class), verdict == null ? null : PqcVerdict.valueOf(verdict),
                row.get("current_verdict", Boolean.class));
    }
}
