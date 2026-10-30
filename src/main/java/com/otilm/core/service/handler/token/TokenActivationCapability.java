package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import java.util.List;

/** Token activation operations, available only on the legacy v1 protocol. */
public interface TokenActivationCapability {

    List<BaseAttribute> listActivationAttributes(TokenInstanceBasicModel tokenInstance) throws ConnectorException;

    void activate(TokenInstanceBasicModel tokenInstance, List<RequestAttribute> attributes) throws ConnectorException;

    void deactivate(TokenInstanceBasicModel tokenInstance) throws ConnectorException;
}
