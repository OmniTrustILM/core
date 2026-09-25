package com.otilm.core.cbom.asset;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import java.util.List;

/**
 * The asset type as the wire serves it: the CycloneDX {@code cryptoProperties.assetType} vocabulary and nothing else.
 *
 * <p>
 * {@link CryptographicAssetType#UNROUTABLE} is a stored tier, not a CycloneDX value. CycloneDX closes the vocabulary
 * with no "unknown", so an asset stored with it is served with no type at all.
 */
public final class ServedAssetType {

    /** The served values, in declaration order. */
    public static final List<CryptographicAssetType> VALUES = List
            .of(CryptographicAssetType.ALGORITHM, CryptographicAssetType.CERTIFICATE, CryptographicAssetType.PROTOCOL,
                    CryptographicAssetType.RELATED_CRYPTO_MATERIAL);

    private ServedAssetType() {
    }

    /** The type to serve for a stored one, or {@code null} when CycloneDX has no value for it. */
    public static CryptographicAssetType of(CryptographicAssetType stored) {
        return VALUES.contains(stored) ? stored : null;
    }
}
