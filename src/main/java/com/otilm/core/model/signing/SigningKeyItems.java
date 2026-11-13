package com.otilm.core.model.signing;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/** Signing uses the private and the public key item first in {@link SigningCertificate#KEY_ITEM_ORDER}. */
public final class SigningKeyItems {

    private SigningKeyItems() {
    }

    public static Optional<CryptographicKeyItemOperationModel> first(KeyType keyType,
            List<CryptographicKeyItemOperationModel> keyItems) {
        return keyItems
                .stream()
                .filter(item -> item.keyType() == keyType)
                .min(Comparator
                        .comparing(CryptographicKeyItemOperationModel::keyItemUuid, SigningCertificate.KEY_ITEM_ORDER));
    }
}
