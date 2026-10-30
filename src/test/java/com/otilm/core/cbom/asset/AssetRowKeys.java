package com.otilm.core.cbom.asset;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * A stable row key for persistence tests, derived from the typed fields alone.
 *
 * <p>
 * <b>This is a test fixture, not the identity rule.</b> The real key is routed by asset type and built from the whole
 * component -- a content digest, a composite resolving a reference across the document, document-scoped refutation --
 * and it is proven byte for byte by the ratified vector suite. None of that is reachable from ten columns, and none of
 * it is what these tests are about: they exercise upsert, dedup, guards and the merge, and for that they need only a
 * key that is a stable function of the fields.
 *
 * <p>
 * It derives from {@link CryptoAssetIdentityFields#normalized()} rather than the raw fields so that the assertions
 * which depend on it keep the meaning they had when the writer computed the key itself -- {@code "AES"} and
 * {@code "  aes  "} must still land on one row. What changed is only where that decision is made: the writer now
 * accepts a key, and the pipeline is what guarantees the key describes the asset.
 */
public final class AssetRowKeys {

    private AssetRowKeys() {
    }

    public static String forFields(CryptoAssetIdentityFields fields) {
        CryptoAssetIdentityFields stored = fields.normalized();
        StringBuilder preimage = new StringBuilder("test-fixture");
        for (String field : new String[]{
                stored.assetType() == null ? null : stored.assetType().name(),
                stored.name(),
                stored.oid(),
                stored.algorithmFamily(),
                stored.primitive(),
                stored.parameterSet(),
                stored.curve(),
                stored.mode(),
                stored.padding(),
                stored.variant()}) {
            // Length-prefixed rather than separator-joined, so no field value can forge a field boundary and make two
            // different fixtures collide -- which would turn a dedup assertion green for the wrong reason.
            preimage.append(field == null ? "-" : field.length() + ":" + field);
        }
        return sha256Hex(preimage.toString());
    }

    /**
     * A plain SHA-256, not the identity chain's. The chain's digest refuses unpaired surrogates because a silently
     * substituted {@code ?} would collide two real pre-images; a fixture that only needs a stable function of ten
     * columns has no such exposure, and depending on the chain for it would tie every persistence test to the ratified
     * decision tables.
     */
    private static String sha256Hex(String text) {
        try {
            return HexFormat
                    .of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
