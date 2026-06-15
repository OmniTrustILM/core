package com.otilm.core.util.builders;

import com.otilm.core.dao.entity.CryptographicKey;

/**
 * Builds an in-memory {@link CryptographicKey}; tests override only the fields whose values drive the
 * assertion under test. Items are attached and persisted by the test's key-seeding helper, not here.
 * Defaults match a bare {@code new CryptographicKey()}; a field is written only when its {@code withXxx}
 * is called.
 */
public class CryptographicKeyBuilder {

    private String name;

    public static CryptographicKeyBuilder aCryptographicKey() {
        return new CryptographicKeyBuilder();
    }

    public CryptographicKeyBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public CryptographicKey build() {
        CryptographicKey key = new CryptographicKey();
        if (name != null) key.setName(name);
        return key;
    }
}
