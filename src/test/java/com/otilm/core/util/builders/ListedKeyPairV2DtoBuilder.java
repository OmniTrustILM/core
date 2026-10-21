package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.core.util.TestPublicKeys;
import java.security.PublicKey;
import java.util.UUID;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;

/**
 * Builds a key pair as a connector lists it: a 2048-bit RSA pair labelled "signer", with a key ID of its own and a
 * freshly generated public key. Tests override only what their scenario turns on.
 */
public final class ListedKeyPairV2DtoBuilder {

    private String keyId = UUID.randomUUID().toString();
    private String label = "signer";
    private KeyAlgorithm algorithm = KeyAlgorithm.RSA;
    private Integer length = 2048;
    private PublicKey publicKey = TestPublicKeys.rsaPublicKey();

    public static ListedKeyPairV2DtoBuilder aListedKeyPair() {
        return new ListedKeyPairV2DtoBuilder();
    }

    public ListedKeyPairV2DtoBuilder withKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public ListedKeyPairV2DtoBuilder withLabel(String label) {
        this.label = label;
        return this;
    }

    public ListedKeyPairV2DtoBuilder withAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public ListedKeyPairV2DtoBuilder withLength(Integer length) {
        this.length = length;
        return this;
    }

    public ListedKeyPairV2DtoBuilder withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /** A pair whose token lacks a public key object for it. */
    public ListedKeyPairV2DtoBuilder withoutPublicKey() {
        this.publicKey = null;
        return this;
    }

    public ListedKeyPairV2Dto build() {
        ListedKeyPairV2Dto listed = new ListedKeyPairV2Dto();
        listed.setKeyPairMeta(keyIdMeta(keyId));
        listed.setLabel(label);
        listed.setPrivateKeyData(privateKeyData());
        if (publicKey != null) {
            listed.setPublicKeyData(publicKeyData());
        }
        return listed;
    }

    private PrivateKeyDataResponseV2Dto privateKeyData() {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setLength(length);
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyMeta(keyIdMeta(keyId));
        privateKey.setKeyData(descriptor);
        return privateKey;
    }

    private PublicKeyDataResponseV2Dto publicKeyData() {
        PublicKeyDataV2Dto descriptor = new PublicKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setLength(length);
        descriptor.setPublicKeySpki(publicKey.getEncoded());
        PublicKeyDataResponseV2Dto publicKeyData = new PublicKeyDataResponseV2Dto();
        publicKeyData.setKeyMeta(keyIdMeta(keyId));
        publicKeyData.setKeyData(descriptor);
        return publicKeyData;
    }
}
