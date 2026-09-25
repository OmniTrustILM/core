package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
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
}
