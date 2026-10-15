package com.otilm.core.provider.key;

import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import java.security.PrivateKey;
import java.util.Objects;

/** Request-scoped handle to a platform key; the adapter owns its connector-specific representation. */
public record PlatformPrivateKey(CryptographicKeyItemOperationModel keyItem) implements PrivateKey {
    public PlatformPrivateKey(CryptographicKeyItemOperationModel keyItem) {
        this.keyItem = Objects.requireNonNull(keyItem, "keyItem must not be null");
    }

    @Override
    public String getAlgorithm() {
        return keyItem.keyAlgorithm().getLabel();
    }

    @Override
    public String getFormat() {
        return "Platform";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public String getKeyUuid() {
        return keyItem.keyItemUuid().toString();
    }
}
