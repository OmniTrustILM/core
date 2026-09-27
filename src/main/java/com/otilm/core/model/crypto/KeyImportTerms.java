package com.otilm.core.model.crypto;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.List;

/**
 * What an import asks of a connector, and who asks it.
 *
 * @param profile the token profile the key is imported into
 * @param type the key type the import asks for
 * @param algorithm the key's algorithm, found in the file
 * @param spkiFingerprint the fingerprint of the key's public key, as the inventory computes it
 * @param exportable whether the key may later be exported
 * @param importAttributes the import attributes, validated against the connector's schema
 * @param requester the user who asks for the import
 */
public record KeyImportTerms(TokenProfileFullModel profile, KeyRequestType type, KeyAlgorithm algorithm,
        String spkiFingerprint, boolean exportable, List<RequestAttribute> importAttributes, NameAndUuidDto requester) {
}
