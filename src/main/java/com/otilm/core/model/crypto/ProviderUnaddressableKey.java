package com.otilm.core.model.crypto;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;

/**
 * A private key a token holds without an identifier unique to it, which onboarding needs.
 *
 * @param label the token's label for the key, or null
 * @param length key length in bits, or null when the algorithm does not require a length
 */
public record ProviderUnaddressableKey(String label, KeyAlgorithm algorithm, Integer length) {
}
