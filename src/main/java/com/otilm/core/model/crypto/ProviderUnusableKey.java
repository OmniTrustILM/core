package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.UnusableKeyReason;

/**
 * A private key a token holds that onboarding cannot take, with the connector's reason.
 *
 * @param label the token's label for the key, or null
 * @param algorithm the key's algorithm, or null when the connector cannot read the key
 * @param length key length in bits, or null when the connector cannot read the key or the algorithm does not require a
 * length
 */
public record ProviderUnusableKey(String label, UnusableKeyReason reason, KeyAlgorithm algorithm, Integer length) {
}
