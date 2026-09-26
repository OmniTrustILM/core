package com.otilm.core.model.crypto;

/**
 * The key an import ended in.
 *
 * @param key the registered key
 * @param repeat whether an earlier request registered it, so this request changed nothing
 */
public record ImportedKey(CryptographicKeyFullModel key, boolean repeat) {
}
