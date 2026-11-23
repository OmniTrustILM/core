package com.otilm.core.key.description;

import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.KeySizeUtil;
import java.security.GeneralSecurityException;
import java.util.Optional;

/** Describes a staged discovered key for the discovery results. */
public final class DiscoveredKeyDescriber {

    private DiscoveredKeyDescriber() {
    }

    /**
     * @param key the staged payload
     * @return the description, empty when the payload's encoding is unreadable or it names no algorithm
     */
    public static Optional<DescribedKey> describe(DiscoveredKeyDto key) {
        Optional<DescribedKey> described;
        if (key.hasPublicKeyInSpkiFormat()) {
            described = decoded(key.getPublicKey()).flatMap(spki -> fromSpki(spki, key));
        } else if (key.getAlgorithmIdentifier() != null) {
            described = decoded(key.getAlgorithmIdentifier())
                    .flatMap(KeyParameters::ofIdentifier)
                    .map(parameters -> KeyDescriber
                            .describe(parameters, key.getType(), key.getAlgorithm(), key.getLength()));
        } else {
            described = Optional.of(KeyDescriber.fromStatement(key.getAlgorithm(), key.getLength()));
        }
        return described.filter(description -> description.algorithm() != null);
    }

    private static Optional<DescribedKey> fromSpki(byte[] spki, DiscoveredKeyDto key) {
        return KeyParameters
                .ofSpki(spki)
                .map(parameters -> KeyDescriber
                        .describe(parameters, key.getType(), key.getAlgorithm(), inventorySize(parameters, spki)));
    }

    /** A key in Core's table takes its size from its parameters. */
    private static Integer inventorySize(KeyParameters parameters, byte[] spki) {
        if (KeyParameterTable.algorithmOf(parameters.identifier().getAlgorithm()).isPresent()) {
            return null;
        }
        try {
            return KeySizeUtil.knownLength(KeySizeUtil.getKeyLength(CryptographyUtil.decodePublicKey(spki)));
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    private static Optional<byte[]> decoded(String material) {
        try {
            return Optional.of(DiscoveredKeyMaterial.decoded(material));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
