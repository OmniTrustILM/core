package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import java.util.UUID;

/**
 * The key that holds a private key's handle on a token instance.
 *
 * @param privateKeyParameterSet the curve or post-quantum parameter set of the key's private key, or null when unknown
 * @param privateKeyLength the size of the key's private key in bits, or null when unknown
 * @param publicKeyFingerprint the fingerprint of the key's public key, or null for a key without one
 * @param active whether every item of the key is active, or yet to become so
 */
public record HandleHolderSummary(UUID keyUuid, String keyName, UUID tokenInstanceUuid,
        KeyAlgorithm privateKeyAlgorithm, String privateKeyParameterSet, Integer privateKeyLength,
        String publicKeyFingerprint, boolean active) {

    /**
     * Whether the key's algorithm, parameter set, size and public key agree with the listed pair's. A key that
     * disagrees held the handle before the token reused it.
     *
     * @param privateKey the listed pair's private key
     * @param listedPublicKeyFingerprint the fingerprint of the listed pair's public key, or null for a pair listed
     * without one
     */
    public boolean agreesWith(ProviderKeyItem privateKey, String listedPublicKeyFingerprint) {
        return knownValuesAgree(readable(privateKeyAlgorithm), readable(privateKey.algorithm()))
                && knownValuesAgree(privateKeyParameterSet, privateKey.parameterSet())
                && knownValuesAgree(privateKeyLength, privateKey.length())
                && knownValuesAgree(publicKeyFingerprint, listedPublicKeyFingerprint);
    }

    /** A value unknown on either side agrees. Only two known values can differ. */
    private static boolean knownValuesAgree(Object held, Object listed) {
        return held == null || listed == null || held.equals(listed);
    }

    private static KeyAlgorithm readable(KeyAlgorithm algorithm) {
        return algorithm == KeyAlgorithm.UNKNOWN ? null : algorithm;
    }

    public PublicKeyHolderSummary asKeyPairHolder() {
        return new PublicKeyHolderSummary(keyUuid, keyName, tokenInstanceUuid, Holding.KEY_PAIR, active);
    }
}
