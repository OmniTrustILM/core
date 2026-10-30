package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;

/** Connector-owned token lifecycle, available only on the legacy v1 protocol. */
public interface RemoteTokenLifecycleCapability {

    TokenInstanceDto createRemoteToken(TokenInstanceRequestDto request) throws ConnectorException;

    TokenInstanceDto updateRemoteToken(TokenInstanceBasicModel tokenInstance, TokenInstanceRequestDto request)
            throws ConnectorException;

    void removeRemoteToken(TokenInstanceBasicModel tokenInstance) throws ConnectorException;
}
