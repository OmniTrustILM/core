package com.otilm.core.model.cbom;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import java.util.Map;
import java.util.UUID;

/**
 * One row the re-evaluation sweep has to restamp: its uuid, its ten identity columns and the merged payload.
 *
 * <p>
 * A projection rather than the entity, deliberately. The sweep's outer transaction stays open for the whole run to hold
 * the advisory lock, so entities read through it would accumulate in the persistence context across every batch -- two
 * {@code jsonb} maps apiece -- and would go stale the moment a batch's native {@code UPDATE} committed behind them. A
 * projection is not managed, so neither happens.
 *
 * <p>
 * It carries no identity key. The sweep has no use for one, and the column that would carry it is the one thing
 * core#2070's redaction ruling depends on never leaving the database.
 */
public record PqcStaleVerdictRow(UUID uuid, CryptographicAssetType assetType, String name, String oid,
        String algorithmFamily, String primitive, String parameterSet, String curve, String mode, String padding,
        String variant, Map<String, Object> mergedCryptoProperties) {

    public CryptoAssetIdentityFields fields() {
        return new CryptoAssetIdentityFields(assetType, name, oid, algorithmFamily, primitive, parameterSet, curve,
                mode, padding, variant);
    }
}
