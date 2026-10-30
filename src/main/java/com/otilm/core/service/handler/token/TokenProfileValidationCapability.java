package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import java.util.List;

/** Connector-side token-profile attribute validation, available only on the legacy v1 protocol. */
public interface TokenProfileValidationCapability {

    void validateTokenProfileAttributes(TokenInstanceBasicModel tokenInstance, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException;
}
