package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;

/**
 * Algorithm, parameter-set name and size that Core derives for one key half.
 *
 * @param parameterSet the curve of an EC key or the parameter set of a post-quantum key, or null when unknown
 * @param length the size in bits, or null when unknown
 */
public record DescribedKey(KeyAlgorithm algorithm, String parameterSet, Integer length) {
}
