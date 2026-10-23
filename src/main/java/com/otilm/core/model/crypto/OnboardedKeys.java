package com.otilm.core.model.crypto;

import java.io.Serializable;
import java.util.List;

/**
 * What a token-key onboarding registered, as its audit record names it: every key a key pair was registered in, a
 * joined record the caller may not see included.
 *
 * @param keys the keys, in the order selected
 */
public record OnboardedKeys(List<OnboardedKey> keys) implements Serializable {

    public OnboardedKeys {
        keys = List.copyOf(keys);
    }

    /** @param intoExistingKey whether the key pair joined a key the inventory held already */
    public record OnboardedKey(String uuid, String name, boolean intoExistingKey) implements Serializable {
    }
}
