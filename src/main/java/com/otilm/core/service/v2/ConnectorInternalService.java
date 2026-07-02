package com.otilm.core.service.v2;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.connector.v2.ConnectorRequestDto;
import com.otilm.core.service.ResourceExtensionService;

import java.util.UUID;

public interface ConnectorInternalService extends ResourceExtensionService {

    /**
     * This method is used to create a new Connector with status WAITING_FOR_APPROVAL. It is used by the ConnectorRegistrationExternalService when a new Connector is registered by itself.
     * **WARNING:** Should not use as replacement for createConnector method, as it will create connector without any authorization check
     * @param request ConnectorRequestDto containing the details of the Connector to be created. The status of the Connector will be set to WAITING_FOR_APPROVAL.
     * @return ConnectorDetailDto containing the details of the created Connector.
     * @throws ConnectorException if there is an error while creating the Connector.
     * @throws AlreadyExistException if a Connector with the same name already exists.
     * @throws AttributeException if there is an error with the attributes of the Connector.
     * @throws NotFoundException if the required resources for creating the Connector are not found.
     */
    ConnectorDetailDto createNewWaitingConnector(ConnectorRequestDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException;

    /**
     * Returns cached connector data shaped for API client routing.
     */
    ApiClientConnectorInfo getConnectorForApiClient(UUID connectorUuid) throws NotFoundException;
}
