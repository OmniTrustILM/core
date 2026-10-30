package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import java.util.List;
import java.util.UUID;

/** Hands a key item's material out through its connector, protected under a passphrase the caller chooses. */
public interface CryptographicKeyExportExternalService {

    /**
     * The attributes the key item's connector takes to export it.
     *
     * @param keyUuid UUID of the key
     * @param keyItemUuid UUID of the key item to export
     * @return the connector's export attribute schema
     * @throws NotFoundException if the key does not exist, or has no such item
     */
    List<BaseAttribute> listExportKeyAttributes(UUID keyUuid, UUID keyItemUuid)
            throws ConnectorException, NotFoundException;

    /**
     * Exports the key item. Every attempt that reaches the key item is recorded in its history.
     *
     * @param keyUuid UUID of the key
     * @param keyItemUuid UUID of the key item to export
     * @param request the passphrase that protects the material, and the export attributes
     * @return the material as the connector exported it, never opened by the platform
     * @throws NotFoundException if the key does not exist, or has no such item
     */
    ExportedKeyMaterial exportKey(UUID keyUuid, UUID keyItemUuid, KeyExportRequestDto request)
            throws ConnectorException, NotFoundException;
}
