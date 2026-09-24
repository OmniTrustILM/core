package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;

/**
 * Builds a {@link DiscoveredKeyDto} as a connector reports it; tests override only the fields their assertion turns on.
 * {@link #withSpki} sets the public part and its format together, because the contract has a key report both or
 * neither.
 */
public class DiscoveredKeyDtoBuilder {

    private KeyType type;
    private KeyAlgorithm algorithm;
    private Integer length;
    private KeyFormat publicKeyFormat;
    private String publicKey;
    private String fingerprint;

    /** A 2048-bit RSA public key with no material yet; add it with {@link #withSpki}. */
    public static DiscoveredKeyDtoBuilder aPublicKey() {
        return new DiscoveredKeyDtoBuilder()
                .withType(KeyType.PUBLIC_KEY)
                .withAlgorithm(KeyAlgorithm.RSA)
                .withLength(2048);
    }

    /** A secret key, reported without a public part, so Core lists it and does not onboard it. */
    public static DiscoveredKeyDtoBuilder aSecretKey() {
        return new DiscoveredKeyDtoBuilder().withType(KeyType.SECRET_KEY).withAlgorithm(KeyAlgorithm.UNKNOWN);
    }

    public DiscoveredKeyDtoBuilder withType(KeyType type) {
        this.type = type;
        return this;
    }

    public DiscoveredKeyDtoBuilder withAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public DiscoveredKeyDtoBuilder withLength(Integer length) {
        this.length = length;
        return this;
    }

    /** Base64 material reported as SubjectPublicKeyInfo. */
    public DiscoveredKeyDtoBuilder withSpki(String publicKey) {
        this.publicKey = publicKey;
        this.publicKeyFormat = KeyFormat.SPKI;
        return this;
    }

    public DiscoveredKeyDtoBuilder withPublicKeyFormat(KeyFormat publicKeyFormat) {
        this.publicKeyFormat = publicKeyFormat;
        return this;
    }

    public DiscoveredKeyDtoBuilder withFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
        return this;
    }

    public DiscoveredKeyDto build() {
        DiscoveredKeyDto key = new DiscoveredKeyDto();
        key.setType(type);
        key.setAlgorithm(algorithm);
        key.setLength(length);
        key.setPublicKeyFormat(publicKeyFormat);
        key.setPublicKey(publicKey);
        key.setFingerprint(fingerprint);
        return key;
    }
}
