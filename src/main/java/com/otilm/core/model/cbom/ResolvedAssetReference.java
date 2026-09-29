package com.otilm.core.model.cbom;

import java.util.UUID;

/**
 * A reference as the ingest writes it: what the document said, and the inventory asset it resolved to.
 *
 * @param ordinal position among the source's references of the same kind, in document order
 * @param targetAssetUuid null when the bom-ref named no component that became an asset, or named it ambiguously
 */
public record ResolvedAssetReference(CryptoAssetReferenceKind kind, int ordinal, String ref, String suite,
        UUID targetAssetUuid) {
}
