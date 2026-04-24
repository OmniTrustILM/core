package com.czertainly.core.service.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.connector.*;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.*;
import com.czertainly.api.model.core.connector.v2.ConnectInfo;
import com.czertainly.api.model.core.connector.v2.ConnectInfoV1;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ConnectorService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service("connectorServiceV1")
@Transactional
public class ConnectorServiceImpl implements ConnectorService {

    private com.czertainly.core.service.v2.ConnectorService connectorServiceV2;

    private ConnectorRepository connectorRepository;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setConnectorServiceV2(com.czertainly.core.service.v2.ConnectorService connectorServiceV2) {
        this.connectorServiceV2 = connectorServiceV2;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.LIST)
    public List<ConnectorDto> listConnectors(SecurityFilter filter, Optional<FunctionGroupCode> functionGroup, Optional<String> kind, Optional<ConnectorStatus> status) {
        List<ConnectorDto> connectors = connectorRepository.findUsingSecurityFilter(filter).stream().map(Connector::mapToDto).toList();
        if (functionGroup.isPresent()) {
            connectors = filterByFunctionGroup(connectors, functionGroup.get());
        }
        if (kind.isPresent()) {
            connectors = filterByKind(connectors, kind.get());
        }
        if (status.isPresent()) {
            connectors = filterByStatus(connectors, status.get());
        }
        return connectors;
    }

    @Override
    public ConnectorDto getConnector(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        var connectorDetailDto = connectorServiceV2.getConnector(uuid);
        return convertToDtoV1(connectorDetailDto);
    }

    @Override
    public ConnectorDto createConnector(ConnectorRequestDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        var requestV2 = new com.czertainly.api.model.core.connector.v2.ConnectorRequestDto();
        requestV2.setName(request.getName());
        requestV2.setUrl(request.getUrl());
        requestV2.setVersion(ConnectorVersion.V1);
        requestV2.setAuthType(request.getAuthType());
        requestV2.setAuthAttributes(request.getAuthAttributes());
        requestV2.setCustomAttributes(request.getCustomAttributes());
        requestV2.setProxyUuid(request.getProxyUuid());
        requestV2.setProxyCode(request.getProxyCode());

        ConnectorDetailDto detailDto = connectorServiceV2.createConnector(requestV2);
        return convertToDtoV1(detailDto);
    }

    @Override
    public ConnectorDto editConnector(SecuredUUID uuid, ConnectorUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        var requestV2 = new com.czertainly.api.model.core.connector.v2.ConnectorUpdateRequestDto();
        requestV2.setUrl(request.getUrl());
        requestV2.setAuthType(request.getAuthType());
        requestV2.setAuthAttributes(request.getAuthAttributes());
        requestV2.setCustomAttributes(request.getCustomAttributes());
        requestV2.setProxyUuid(request.getProxyUuid());

        ConnectorDetailDto detailDto = connectorServiceV2.editConnector(uuid, requestV2);
        return convertToDtoV1(detailDto);
    }

    @Override
    public void deleteConnector(SecuredUUID uuid) throws NotFoundException {
        connectorServiceV2.deleteConnector(uuid);
    }

    @Override
    public List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException {
        return connectorServiceV2.bulkDeleteConnector(uuids);
    }

    @Override
    public List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids) throws ValidationException, NotFoundException {
        return connectorServiceV2.forceDeleteConnector(uuids);
    }

    @Override
    public List<ConnectDto> connect(ConnectRequestDto request) throws ValidationException, ConnectorException {
        var connectInfos = connectorServiceV2.connect(request);

        List<ConnectDto> connectDtos = new ArrayList<>();
        for (ConnectInfo connectInfo : connectInfos) {
            if (connectInfo.getVersion() != ConnectorVersion.V1) {
                continue;
            }

            if (connectInfo.getErrorMessage() != null) {
                throw new ValidationException(connectInfo.getErrorMessage());
            }

            ConnectInfoV1 connectInfoV1 = (ConnectInfoV1) connectInfo;
            for (FunctionGroupDto functionGroupDto : connectInfoV1.getFunctionGroups()) {
                ConnectDto connectDto = new ConnectDto();
                connectDto.setFunctionGroup(functionGroupDto);
                connectDtos.add(connectDto);
            }
        }

        return connectDtos;
    }

    @Override
    public List<ConnectDto> reconnect(SecuredUUID uuid) throws ValidationException, ConnectorException, NotFoundException {
        var connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        if (connector.getVersion() != ConnectorVersion.V1) {
            throw new ValidationException("Expected connector version " + ConnectorVersion.V1.getLabel() + " but got " + connector.getVersion().getLabel());
        }

        var connectInfo = connectorServiceV2.reconnect(uuid);
        List<ConnectDto> connectDtos = new ArrayList<>();
        ConnectInfoV1 connectInfoV1 = (ConnectInfoV1) connectInfo;
        for (FunctionGroupDto functionGroupDto : connectInfoV1.getFunctionGroups()) {
            ConnectDto connectDto = new ConnectDto();
            connectDto.setFunctionGroup(functionGroupDto);
            connectDtos.add(connectDto);
        }

        return connectDtos;
    }

    @Override
    public void reconnect(List<SecuredUUID> uuids) throws ValidationException, ConnectorException {
        connectorServiceV2.bulkReconnect(uuids);
    }

    @Override
    public void approve(SecuredUUID uuid) throws NotFoundException, ValidationException {
        connectorServiceV2.approve(uuid);
    }

    @Override
    public void approve(List<SecuredUUID> uuids) throws NotFoundException, ValidationException {
        connectorServiceV2.bulkApprove(uuids);
    }

    @Override
    public HealthDto checkHealth(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        return connectorApiFactory.getHealthApiClient(connectorDto).checkHealth(connectorDto);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public List<BaseAttribute> getAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, String functionGroupType) throws ConnectorException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        validateFunctionGroup(connector, functionGroup);

        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        return connectorApiFactory.getAttributeApiClient(connectorDto).listAttributeDefinitions(connectorDto, functionGroup, functionGroupType);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public void validateAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, List<RequestAttribute> attributes, String functionGroupType) throws ValidationException, ConnectorException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        validateAttributes(connector, functionGroup, attributes, functionGroupType);
    }

    private void validateAttributes(Connector connector, FunctionGroupCode functionGroup, List<RequestAttribute> attributes, String functionGroupType) throws ValidationException, ConnectorException {
        validateFunctionGroup(connector, functionGroup);
        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        connectorApiFactory.getAttributeApiClient(connectorDto).validateAttributes(connectorDto, functionGroup, attributes, functionGroupType);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public void mergeAndValidateAttributes(SecuredUUID uuid, FunctionGroupCode functionGroup, List<RequestAttribute> requestAttributes, String functionGroupType) throws ValidationException, ConnectorException, AttributeException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        // validate first by connector
        validateAttributes(connector, functionGroup, requestAttributes, functionGroupType);

        // get definitions from connector
        ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
        List<BaseAttribute> definitions = connectorApiFactory.getAttributeApiClient(connectorDto).listAttributeDefinitions(connectorDto, functionGroup, functionGroupType);

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(connector.getUuid(), null, definitions, requestAttributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public Map<FunctionGroupCode, Map<String, List<BaseAttribute>>> getAllAttributesOfConnector(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        Connector connector = connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));

        ConnectorDto connectorDto = connector.mapToDto();
        Map<FunctionGroupCode, Map<String, List<BaseAttribute>>> attributes = new EnumMap<>(FunctionGroupCode.class);
        for (FunctionGroupDto fg : connectorDto.getFunctionGroups()) {
            Map<String, List<BaseAttribute>> kindsAttribute = new HashMap<>();
            for (String kind : fg.getKinds()) {
                kindsAttribute.put(kind, connectorApiFactory.getAttributeApiClient(connectorDto).listAttributeDefinitions(connectorDto, fg.getFunctionGroupCode(), kind));
            }
            attributes.put(fg.getFunctionGroupCode(), kindsAttribute);
        }
        return attributes;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return connectorServiceV2.getResourceObjectInternal(objectUuid);
    }

    @Override
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return connectorServiceV2.getResourceObjectExternal(objectUuid);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return connectorServiceV2.listResourceObjects(filter, filters, pagination);
    }

    @Override
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        connectorServiceV2.evaluatePermissionChain(uuid);
    }

    private void validateFunctionGroup(Connector connector, FunctionGroupCode functionGroup) {
        Connector2FunctionGroup connector2FunctionGroup = null;
        for (Connector2FunctionGroup c2fg : connector.getFunctionGroups()) {
            if (c2fg.getFunctionGroup().getCode().equals(functionGroup)) {
                connector2FunctionGroup = c2fg;
            }
        }

        if (connector2FunctionGroup == null) {
            throw new ValidationException(ValidationError.create("Connector {} doesn't support function group code {}", connector.getName(), functionGroup));
        }
    }

    private List<ConnectorDto> filterByFunctionGroup(List<ConnectorDto> connectors, FunctionGroupCode code) {
        List<ConnectorDto> connectorDtos = new ArrayList<>();
        for (ConnectorDto connectorDto : connectors) {
            for (FunctionGroupDto fg : connectorDto.getFunctionGroups()) {
                if (code == FunctionGroupCode.AUTHORITY_PROVIDER) {
                    if (Arrays.asList(FunctionGroupCode.AUTHORITY_PROVIDER, FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER).contains(fg.getFunctionGroupCode())) {
                        connectorDto.setFunctionGroups(List.of(fg));
                        connectorDtos.add(connectorDto);
                    }
                } else {
                    if (fg.getFunctionGroupCode() == code) {
                        connectorDto.setFunctionGroups(List.of(fg));
                        connectorDtos.add(connectorDto);
                    }
                }
            }
        }
        return connectorDtos;
    }

    private List<ConnectorDto> filterByKind(List<ConnectorDto> connectors, String kind) {
        List<ConnectorDto> connectorDtos = new ArrayList<>();
        for (ConnectorDto connectorDto : connectors) {
            for (FunctionGroupDto fg : connectorDto.getFunctionGroups()) {
                if (fg.getKinds().contains(kind)) {
                    connectorDtos.add(connectorDto);
                }
            }
        }
        return connectorDtos;
    }

    private List<ConnectorDto> filterByStatus(List<ConnectorDto> connectors, ConnectorStatus status) {
        List<ConnectorDto> connectorDtos = new ArrayList<>();
        for (ConnectorDto connectorDto : connectors) {
            if (connectorDto.getStatus().equals(status)) {
                connectorDtos.add(connectorDto);
            }
        }
        return connectorDtos;
    }

    private ConnectorDto convertToDtoV1(ConnectorDetailDto connectorDetailDto) {
        ConnectorDto dto = new ConnectorDto();
        dto.setUuid(connectorDetailDto.getUuid());
        dto.setName(connectorDetailDto.getName());
        dto.setUrl(connectorDetailDto.getUrl());
        dto.setStatus(connectorDetailDto.getStatus());
        dto.setAuthType(connectorDetailDto.getAuthType());
        dto.setAuthAttributes(connectorDetailDto.getAuthAttributes());
        dto.setFunctionGroups(connectorDetailDto.getFunctionGroups());
        dto.setCustomAttributes(connectorDetailDto.getCustomAttributes());
        dto.setProxy(connectorDetailDto.getProxy());

        return dto;
    }

}
