package com.czertainly.core.service;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.connector.ConnectDto;
import com.czertainly.api.model.client.connector.ConnectRequestDto;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.client.connector.ConnectorUpdateRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface ConnectorService extends ResourceExtensionService {

    Map<FunctionGroupCode, Map<String, List<BaseAttribute>>> getAllAttributesOfConnector(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<ConnectorDto> listConnectors(SecurityFilter filter, Optional<FunctionGroupCode> functionGroup, Optional<String> kind, Optional<ConnectorStatus> status) throws NotFoundException;

    ConnectorDto getConnector(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    ConnectorDto createConnector(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    ConnectorDto editConnector(SecuredUUID uuid, ConnectorUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteConnector(SecuredUUID uuid) throws NotFoundException;

    void approve(List<SecuredUUID> uuids) throws NotFoundException, ValidationException;

    List<ConnectDto> connect(ConnectRequestDto request) throws ValidationException, ConnectorException;

    List<ConnectDto> reconnect(SecuredUUID uuid) throws ValidationException, ConnectorException, NotFoundException;

    void reconnect(List<SecuredUUID> uuids) throws ValidationException, ConnectorException;

    void approve(SecuredUUID uuid) throws NotFoundException, ValidationException;

    HealthDto checkHealth(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<BaseAttribute> getAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, String functionGroupType) throws ConnectorException, NotFoundException;

    void validateAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, List<RequestAttribute> attributes, String functionGroupType) throws ValidationException, ConnectorException, NotFoundException;

    void mergeAndValidateAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, List<RequestAttribute> attributes, String functionGroupType) throws ConnectorException, AttributeException, NotFoundException;

    List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;

    List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;

    ApiClientConnectorInfo getConnectorForApiClient(UUID connectorUuid) throws NotFoundException;
}
