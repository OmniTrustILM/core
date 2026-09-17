package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import java.util.List;

/** Connector-side key creation attribute validation, available only on the legacy v1 protocol. */
public interface KeyCreationValidationCapability {

    /**
     * Validates creation attributes against the provider's rules for the requested key type.
     *
     * @param tokenInstance the non-null token instance identifying the provider token
     * @param type the non-null key request type
     * @param attributes the non-null creation attributes submitted by the caller
     * @throws ValidationException if the provider rejects the creation attributes
     * @throws ConnectorException if the provider validation operation fails
     */
    void validateCreateKeyAttributes(TokenInstanceBasicModel tokenInstance, KeyRequestType type,
            List<RequestAttribute> attributes) throws ValidationException, ConnectorException;
}
