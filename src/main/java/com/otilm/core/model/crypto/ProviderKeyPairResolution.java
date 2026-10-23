package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionOutcome;

/**
 * The token's answer for one key pair handle.
 *
 * @param keyPair the key pair the token holds under the handle, present exactly when the outcome is found
 */
public record ProviderKeyPairResolution(KeyResolutionOutcome outcome, ProviderKeyPair keyPair) {
}
