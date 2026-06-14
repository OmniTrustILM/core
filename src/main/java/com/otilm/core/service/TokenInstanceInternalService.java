package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;

public interface TokenInstanceInternalService extends ResourceExtensionService {
    /**
     * Get the token instance entity
     *
     * @param uuid UUID of the token instance
     * @return the {@link TokenInstanceReference} entity
     * @throws NotFoundException when the token instance is not found
     */
    TokenInstanceReference getTokenInstanceEntity(SecuredUUID uuid) throws NotFoundException;

    /**
     * Validate the token Profile attributes
     *
     * @param uuid       UUID of the token instance
     * @param attributes attributes to be validated
     * @throws ConnectorException when there are issues with the communication
     * @throws NotFoundException  when the token instance is not found
     */
    void validateTokenProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException;
}
