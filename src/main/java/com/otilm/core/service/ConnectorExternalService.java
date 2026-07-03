package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.ConnectDto;
import com.otilm.api.model.client.connector.ConnectRequestDto;
import com.otilm.api.model.client.connector.ConnectorRequestDto;
import com.otilm.api.model.client.connector.ConnectorUpdateRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.HealthDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface ConnectorExternalService {

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

    List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;

    List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;
}
