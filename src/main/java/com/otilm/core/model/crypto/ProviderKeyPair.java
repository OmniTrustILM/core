package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import java.util.List;

/**
 * A key pair listed on a token, as a candidate for onboarding.
 *
 * @param keyPairMeta the provider's handle for the pair
 * @param label the token's label for the pair, or null
 * @param publicKey the public key item, or null when the token holds none
 */
public record ProviderKeyPair(List<MetadataAttribute> keyPairMeta, String label, ProviderKeyItem privateKey,
        ProviderKeyItem publicKey) {

    public ProviderKeyPair {
        keyPairMeta = List.copyOf(keyPairMeta);
    }

    /**
     * The pair's items under the onboarded key's name, ordered and named as key creation orders and names them.
     *
     * @throws IllegalStateException for a pair listed without its public key
     */
    public List<ProviderKeyItem> itemsNamed(String keyName) {
        if (publicKey == null) {
            throw new IllegalStateException("A key pair listed without its public key cannot be onboarded");
        }
        ProviderKeyItem publicKeyItem = named(publicKey, publicKeyName(keyName));
        ProviderKeyItem privateKeyItem = named(privateKey, privateKeyName(keyName));
        return List.of(publicKeyItem, privateKeyItem);
    }

    public static String publicKeyName(String keyName) {
        return keyName + " public key";
    }

    public static String privateKeyName(String keyName) {
        return keyName + " private key";
    }

    private static ProviderKeyItem named(ProviderKeyItem item, String name) {
        return new ProviderKeyItem(name, item.type(), item.algorithm(), item.length(), item.reference(),
                item.material(), item.metadata(), item.association());
    }
}
