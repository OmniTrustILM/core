package com.otilm.core.service.handler.key;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.UUID;

/**
 * What the platform holds about a key it asks a connector to export, to check the key the connector says it exported.
 *
 * @param type what the export is of
 * @param algorithm the key's algorithm
 * @param length the key's length
 * @param publicKeySpki the DER SubjectPublicKeyInfo of the pair's public key, {@code null} for a secret key
 * @param keyReference the platform's own reference to the key, {@code null} when it has none
 */
// S6218: nothing compares, hashes or prints this value; it only carries the key to the adapter's check.
@SuppressWarnings("java:S6218")
public record HeldKey(KeyRequestType type, KeyAlgorithm algorithm, int length, byte[] publicKeySpki,
        UUID keyReference) {
}
