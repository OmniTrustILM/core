package com.otilm.core.model.crypto;

import java.util.List;

/**
 * A page of listed key pairs, with the size of the whole listing.
 *
 * @param unusableKeys the page's keys that onboarding cannot take
 */
public record ProviderKeyPairPage(List<ProviderKeyPair> keyPairs, List<ProviderUnusableKey> unusableKeys,
        long totalItems) {

    public ProviderKeyPairPage {
        keyPairs = List.copyOf(keyPairs);
        unusableKeys = List.copyOf(unusableKeys);
    }
}
