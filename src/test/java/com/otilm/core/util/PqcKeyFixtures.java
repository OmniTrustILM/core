package com.otilm.core.util;

import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Real ML-DSA key material and connector descriptors with an omitted length.
 */
public final class PqcKeyFixtures {

    private PqcKeyFixtures() {
    }

    /**
     * Generates an ML-DSA-65 pair for key identity checks.
     *
     * @return a pair with valid DER public material
     * @throws GeneralSecurityException if the algorithm is unavailable
     */
    public static KeyPair keyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA-65", new BouncyCastleProvider());
        return generator.generateKeyPair();
    }

    /**
     * Describes an imported or created pair without claiming a conventional bit length.
     *
     * @param pair real ML-DSA pair
     * @return connector response with distinct handles and null lengths
     */
    public static KeyPairDataResponseV2Dto response(KeyPair pair) {
        PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
        publicData.setAlgorithm(KeyAlgorithm.MLDSA);
        publicData.setPublicKeySpki(pair.getPublic().getEncoded());
        PublicKeyDataResponseV2Dto publicKey = new PublicKeyDataResponseV2Dto();
        publicKey.setKeyData(publicData);
        publicKey.setKeyMeta(List.of(handle("public-handle")));
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(KeyAlgorithm.MLDSA);
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyData(privateData);
        privateKey.setKeyMeta(List.of(handle("private-handle")));
        KeyPairDataResponseV2Dto response = new KeyPairDataResponseV2Dto();
        response.setPublicKeyData(publicKey);
        response.setPrivateKeyData(privateKey);
        response.setKeyPairMeta(List.of(handle("pair-handle")));
        return response;
    }

    private static MetadataAttributeV2 handle(String name) {
        MetadataAttributeV2 handle = new MetadataAttributeV2();
        handle.setName(name);
        return handle;
    }
}
