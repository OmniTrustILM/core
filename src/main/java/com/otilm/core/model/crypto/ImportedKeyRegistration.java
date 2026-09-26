package com.otilm.core.model.crypto;

import com.otilm.api.model.common.NameAndUuidDto;
import java.util.List;
import java.util.UUID;

/**
 * An imported key as it is registered: the items the connector describes, and what the platform adds to them.
 *
 * @param profile the token profile the key was imported into
 * @param items the key's items as the connector describes them
 * @param keyReference the reference the connector bound the key to, which the private item carries
 * @param spkiFingerprint the fingerprint of the key's public key
 * @param exportable whether the private item may later be exported
 * @param metadata the name, description and groups the key is registered with
 * @param owner the user who imported the key
 */
public record ImportedKeyRegistration(TokenProfileFullModel profile, List<ProviderKeyItem> items, UUID keyReference,
        String spkiFingerprint, boolean exportable, KeyImportMetadata metadata, NameAndUuidDto owner) {
}
