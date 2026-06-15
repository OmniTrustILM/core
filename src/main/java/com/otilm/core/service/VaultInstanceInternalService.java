package com.otilm.core.service;


import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.secrets.SecretOperationRequest;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.UUID;

public interface VaultInstanceInternalService {

    void loadAttributesForSecretOperation(ApiClientConnectorInfo connector, UUID vaultInstanceUuid, UUID vaultProfileUuid, SecretOperationRequest secretOperationRequest) throws NotFoundException, ConnectorException, AttributeException;

    Long statisticsVaultInstanceCount(SecurityFilter filter);
}
