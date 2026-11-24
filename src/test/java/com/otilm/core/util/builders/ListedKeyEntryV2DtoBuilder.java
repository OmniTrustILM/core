package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.core.util.TestPublicKeys;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;

/**
 * An entry of a key pair listing, by default an available RSA 2048 pair named {@code signer} with a fresh key id.
 * {@link #anUnusableKey()} builds an unaddressable {@code legacy} entry, which carries only the key's descriptor.
 */
public final class ListedKeyEntryV2DtoBuilder {

    private KeyEntryStatus status = KeyEntryStatus.AVAILABLE;
    private String diagnostic;
    private String storageName = "signer";
    private String keyId = UUID.randomUUID().toString();
    private KeyAlgorithm algorithm = KeyAlgorithm.RSA;
    private Integer length = 2048;
    private byte[] algorithmIdentifier;
    private PublicKey publicKey;
    private boolean publicKeyOnToken = true;
    private boolean keyDataRead = true;
    private List<MetadataAttribute> metadata;

    public static ListedKeyEntryV2DtoBuilder aListedKeyPair() {
        return new ListedKeyEntryV2DtoBuilder();
    }

    public static ListedKeyEntryV2DtoBuilder anUnusableKey() {
        return new ListedKeyEntryV2DtoBuilder()
                .withStatus(KeyEntryStatus.UNADDRESSABLE)
                .withStorageName("legacy")
                .withMetadata(List.of());
    }

    /** The handle of the key pair an entry carries. */
    public static List<MetadataAttribute> keyPairMetaOf(ListedKeyEntryV2Dto entry) {
        return ((ListedKeyPairV2Dto) entry.getKey()).getKeyPairMeta();
    }

    public ListedKeyEntryV2DtoBuilder withStatus(KeyEntryStatus status) {
        this.status = status;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withDiagnostic(String diagnostic) {
        this.diagnostic = diagnostic;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withStorageName(String storageName) {
        this.storageName = storageName;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withLength(Integer length) {
        this.length = length;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withAlgorithmIdentifier(byte[] algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        this.publicKeyOnToken = true;
        return this;
    }

    /** A pair whose token lacks a public key object for it. */
    public ListedKeyEntryV2DtoBuilder withoutPublicKey() {
        this.publicKeyOnToken = false;
        return this;
    }

    public ListedKeyEntryV2DtoBuilder withMetadata(List<MetadataAttribute> metadata) {
        this.metadata = metadata;
        return this;
    }

    /** The connector could not read the key's type. */
    public ListedKeyEntryV2DtoBuilder withoutKeyData() {
        this.keyDataRead = false;
        return this;
    }

    public ListedKeyEntryV2Dto build() {
        ListedKeyEntryV2Dto entry = new ListedKeyEntryV2Dto();
        entry.setStatus(status);
        entry.setDiagnostic(diagnostic);
        entry.setStorageName(storageName);
        if (status.carriesListedKey()) {
            entry.setKey(buildKeyPair());
        } else if (keyDataRead && status.matchesKey()) {
            entry.setKeyData(descriptor());
        }
        return entry;
    }

    public ListedKeyPairV2Dto buildKeyPair() {
        ListedKeyPairV2Dto listed = new ListedKeyPairV2Dto();
        listed.setKeyPairMeta(keyIdMeta(keyId));
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyMeta(keyIdMeta(keyId));
        privateKey.setKeyData(descriptor());
        listed.setPrivateKeyData(privateKey);
        if (publicKeyOnToken) {
            listed.setPublicKeyData(publicKeyData());
        }
        return listed;
    }

    private PrivateKeyDataV2Dto descriptor() {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setLength(length);
        descriptor.setAlgorithmIdentifier(algorithmIdentifier);
        descriptor.setMetadata(metadata);
        return descriptor;
    }

    /** Generating an RSA key takes time, so only an entry carrying a public key generates one. */
    private PublicKey publicKey() {
        if (publicKey == null) {
            publicKey = TestPublicKeys.rsaPublicKey();
        }
        return publicKey;
    }

    private PublicKeyDataResponseV2Dto publicKeyData() {
        PublicKeyDataV2Dto descriptor = new PublicKeyDataV2Dto();
        descriptor.setAlgorithm(algorithm);
        descriptor.setPublicKeySpki(publicKey().getEncoded());
        PublicKeyDataResponseV2Dto publicKeyData = new PublicKeyDataResponseV2Dto();
        publicKeyData.setKeyMeta(keyIdMeta(keyId));
        publicKeyData.setKeyData(descriptor);
        return publicKeyData;
    }
}
