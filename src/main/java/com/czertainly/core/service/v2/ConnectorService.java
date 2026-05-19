package com.czertainly.core.service.v2;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.ConnectRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorInfo;
import com.czertainly.api.model.client.connector.v2.HealthInfo;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.connector.v2.*;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ResourceExtensionService;

import java.util.List;
import java.util.UUID;

public interface ConnectorService extends ResourceExtensionService {

    PaginationResponseDto<ConnectorDto> listConnectors(SecurityFilter filter, SearchRequestDto request);

    ConnectorDetailDto getConnector(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    ConnectorDetailDto createConnector(ConnectorRequestDto request) throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException;

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

    ConnectorDetailDto editConnector(SecuredUUID uuid, ConnectorUpdateRequestDto request) throws NotFoundException, ConnectorException, AttributeException;

    void deleteConnector(SecuredUUID uuid) throws NotFoundException;

    List<ConnectInfo> connect(ConnectRequestDto request) throws ConnectorException;

    ConnectInfo reconnect(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    void approve(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkApprove(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> bulkReconnect(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids);

    HealthInfo checkHealth(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    ConnectorInfo getInfo(SecuredUUID uuid) throws NotFoundException, ConnectorException;

    List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup();

    /**
     * Returns cached connector data shaped for API client routing.
     */
    ApiClientConnectorInfo getConnectorForApiClient(UUID connectorUuid) throws NotFoundException;
}
