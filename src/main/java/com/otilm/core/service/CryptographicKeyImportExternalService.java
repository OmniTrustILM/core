package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.ImportedKeyDetail;
import java.util.List;
import java.util.UUID;

/** Brings key material into a token through its connector. */
public interface CryptographicKeyImportExternalService {

    /**
     * The attributes the token profile's connector takes to import a key of the type.
     *
     * @param tokenInstanceUuid UUID of the token
     * @param tokenProfileUuid UUID of the token profile to import into
     * @param type type of the key to import
     * @return the connector's import attribute schema
     * @throws NotFoundException if the token has no such token profile
     */
    List<BaseAttribute> listImportKeyAttributes(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type)
            throws ConnectorException, NotFoundException;

    /**
     * Imports a key from an uploaded file into the token profile. The file is opened in the platform and the key
     * protected afresh, so neither the file nor its passphrase reaches the connector.
     *
     * @param tokenInstanceUuid UUID of the token
     * @param tokenProfileUuid UUID of the token profile to import into
     * @param type type of the key to import
     * @param request the file, its passphrase and the key's metadata
     * @return the key and what became of it
     * @throws NotFoundException if the token has no such token profile, or a group does not exist
     * @throws ValidationException with a fixed message when the platform or the connector refuses the import
     * @throws ConnectorException with a fixed message when the connector fails, or the outcome is not confirmed
     */
    ImportedKeyDetail importKey(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException;

    /**
     * Imports a key as {@link #importKey} does, and gives the key itself with what became of it: registered as a key of
     * its own, taken into the public-key-only record that holds its public key, or found in the inventory, changed in
     * nothing. Whether the caller may see the key is for the caller to decide.
     *
     * @param tokenInstanceUuid UUID of the token
     * @param tokenProfileUuid UUID of the token profile to import into
     * @param type type of the key to import
     * @param request the file, its passphrase and the key's metadata
     * @return the key and what became of it
     * @throws NotFoundException if the token has no such token profile, or a group does not exist
     * @throws ValidationException with a fixed message when the platform or the connector refuses the import
     * @throws ConnectorException with a fixed message when the connector fails, or the outcome is not confirmed
     */
    ImportedKey importKeyWithOutcome(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException;
}
