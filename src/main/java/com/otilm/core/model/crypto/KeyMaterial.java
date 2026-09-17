package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;

/** Key representation serialized using Core's key-value serialization convention. */
public record KeyMaterial(KeyFormat format, String serializedValue) {
}
