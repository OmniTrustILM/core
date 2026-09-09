package com.otilm.core.model.cbom;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import jakarta.persistence.Tuple;
import java.util.UUID;

/**
 * One row of the re-evaluation sweep's work list, exactly as the database holds it.
 *
 * @param rowVersion the row's {@code xmin} as read -- the transaction that wrote this version of it. The guarded write
 * refuses the row once another transaction has replaced it, which a timestamp cannot detect because two transactions
 * beginning together share {@code CURRENT_TIMESTAMP}.
 * @param mergedCryptoPropertiesJson the merged payload as stored text, null when the asset has no source payload. Text
 * rather than a {@code Map} because the rules read a {@code JsonNode}: converting to a map would only cost a second
 * serialization.
 */
public record PqcStaleVerdictRow(UUID uuid, CryptographicAssetType assetType, String name, String oid,
        String algorithmFamily, String primitive, String parameterSet, String curve, String mode, String padding,
        String variant, String mergedCryptoPropertiesJson, long rowVersion) {

    /** Reads {@code CryptoAssetRepository.findStaleVerdictRows}'s columns by name; the SELECT list is its contract. */
    public static PqcStaleVerdictRow fromWorkListRow(Tuple row) {
        return new PqcStaleVerdictRow(row.get("uuid", UUID.class),
                CryptographicAssetType.valueOf(row.get("asset_type", String.class)), row.get("name", String.class),
                row.get("oid", String.class), row.get("algorithm_family", String.class),
                row.get("primitive", String.class), row.get("parameter_set", String.class),
                row.get("curve", String.class), row.get("mode", String.class), row.get("padding", String.class),
                row.get("variant", String.class), row.get("merged_crypto_properties", String.class),
                row.get("row_version", Long.class));
    }

    public CryptoAssetIdentityFields fields() {
        return new CryptoAssetIdentityFields(assetType, name, oid, algorithmFamily, primitive, parameterSet, curve,
                mode, padding, variant);
    }
}
