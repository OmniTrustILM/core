package com.otilm.core.model.crypto;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import java.util.List;

/**
 * The data of a key pair a connector listed or resolved. The enclosing {@link ProviderKeyEntry} says whether the pair
 * may be onboarded.
 *
 * @param keyPairMeta the provider's handle for the pair
 * @param publicKey the public key item, or null when the token holds none
 */
public record ProviderKeyPair(List<MetadataAttribute> keyPairMeta, ProviderKeyItem privateKey,
        ProviderKeyItem publicKey) {

    public ProviderKeyPair {
        keyPairMeta = List.copyOf(keyPairMeta);
    }

    public boolean isPrivateOnly() {
        return publicKey == null;
    }

    /** The items of a key onboarded under the given name, named and ordered as for a created key. */
    public List<ProviderKeyItem> toOnboardedItems(String keyName) {
        ProviderKeyItem privateKeyItem = named(privateKey, privateKeyName(keyName));
        if (isPrivateOnly()) {
            return List.of(privateKeyItem);
        }
        ProviderKeyItem publicKeyItem = named(publicKey, publicKeyName(keyName));
        return List.of(publicKeyItem, privateKeyItem);
    }

    public static String publicKeyName(String keyName) {
        return keyName + " public key";
    }

    public static String privateKeyName(String keyName) {
        return keyName + " private key";
    }

    private static ProviderKeyItem named(ProviderKeyItem item, String name) {
        return new ProviderKeyItem(name, item.type(), item.algorithm(), item.parameterSet(), item.length(),
                item.reference(), item.material(), item.metadata(), item.association());
    }
}
