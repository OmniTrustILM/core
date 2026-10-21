package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.util.TestPublicKeys;
import java.security.PublicKey;
import java.util.UUID;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;
import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;

/**
 * Builds a key pair as the key provider adapter reads it from a listing: a 2048-bit RSA pair labelled "signer", with a
 * key ID of its own and a freshly generated public key. Tests override only what their scenario turns on.
 */
public final class ProviderKeyPairBuilder {

    private String keyId = UUID.randomUUID().toString();
    private String label = "signer";
    private PublicKey publicKey = TestPublicKeys.rsaPublicKey();

    public static ProviderKeyPairBuilder aProviderKeyPair() {
        return new ProviderKeyPairBuilder();
    }

    public ProviderKeyPairBuilder withKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public ProviderKeyPairBuilder withLabel(String label) {
        this.label = label;
        return this;
    }

    public ProviderKeyPairBuilder withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public ProviderKeyPair build() {
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(keyIdMeta(keyId));
        ProviderKeyItem privateKeyItem = aProviderKeyItem().withReference(reference).build();
        ProviderKeyItem publicKeyItem = aProviderKeyItem()
                .withType(KeyType.PUBLIC_KEY)
                .withReference(reference)
                .withMaterial(new KeyMaterial(KeyFormat.SPKI, TestPublicKeys.spkiBase64(publicKey)))
                .build();
        return new ProviderKeyPair(keyIdMeta(keyId), label, privateKeyItem, publicKeyItem);
    }
}
