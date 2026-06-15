package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKeyItem;

/**
 * Builds an in-memory {@link CryptographicKeyItem}; tests override only the fields whose values drive the
 * assertion under test. The item is not linked to its key here — persistence helpers wire {@code key} and
 * save through the repositories. Defaults match a bare {@code new CryptographicKeyItem()}; a field is
 * written only when its {@code withXxx} is called.
 */
public class CryptographicKeyItemBuilder {

    private String name;
    private KeyType type;
    private KeyState state;

    public static CryptographicKeyItemBuilder aKeyItem() {
        return new CryptographicKeyItemBuilder();
    }

    public CryptographicKeyItemBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public CryptographicKeyItemBuilder withType(KeyType type) {
        this.type = type;
        return this;
    }

    public CryptographicKeyItemBuilder withState(KeyState state) {
        this.state = state;
        return this;
    }

    public CryptographicKeyItem build() {
        CryptographicKeyItem item = new CryptographicKeyItem();
        if (name != null) item.setName(name);
        if (type != null) item.setType(type);
        if (state != null) item.setState(state);
        return item;
    }
}
