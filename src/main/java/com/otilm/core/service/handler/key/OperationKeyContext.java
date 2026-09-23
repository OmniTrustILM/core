package com.otilm.core.service.handler.key;

import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import java.util.Objects;

/**
 * Key item plus the token-profile scope a stateless provider needs. The profile is null for a legacy v1 item, whose
 * provider is addressed by remote UUIDs instead.
 */
public record OperationKeyContext(CryptographicKeyItemOperationModel keyItem, TokenProfileBasicModel tokenProfile) {

    public OperationKeyContext {
        Objects.requireNonNull(keyItem, "A key item is required.");
    }

    public static OperationKeyContext legacy(CryptographicKeyItemOperationModel keyItem) {
        return new OperationKeyContext(keyItem, null);
    }
}
