package com.otilm.core.model.crypto;

import java.util.List;

/**
 * A page of listed key pairs, with the size of the whole listing.
 *
 * @param unaddressableKeys the page's keys without an identifier unique to them
 */
public record ProviderKeyPairPage(List<ProviderKeyPair> keyPairs, List<ProviderUnaddressableKey> unaddressableKeys,
        long totalItems) {

    public ProviderKeyPairPage {
        keyPairs = List.copyOf(keyPairs);
        unaddressableKeys = List.copyOf(unaddressableKeys);
    }
}
