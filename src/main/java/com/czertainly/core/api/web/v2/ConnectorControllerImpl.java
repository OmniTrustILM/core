package com.czertainly.core.api.web.v2;

import com.otilm.api.exception.*;
import com.otilm.api.interfaces.core.web.v2.ConnectorController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.ConnectRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.v2.*;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.v2.ConnectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.net.ConnectException;
import java.util.List;
import java.util.UUID;

@RestController
public class ConnectorControllerImpl implements ConnectorController {

    private ConnectorService connectorService;

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Override
    @AuthEndpoint(resourceName = Resource.CONNECTOR)
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.LIST)
    public PaginationResponseDto<ConnectorDto> listConnectors(SearchRequestDto request) throws NotFoundException {
        return connectorService.listConnectors(SecurityFilter.create(), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.CONNECTOR, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return connectorService.getSearchableFieldInformationByGroup();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.DETAIL)
    public ConnectorDetailDto getConnector(UUID uuid) throws NotFoundException, ConnectorException {
        return connectorService.getConnector(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.CREATE)
    public ConnectorDetailDto createConnector(ConnectorRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        return connectorService.createConnector(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.UPDATE)
    public ConnectorDetailDto editConnector(UUID uuid, ConnectorUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return connectorService.editConnector(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.DELETE)
    public void deleteConnector(UUID uuid) throws NotFoundException {
        connectorService.deleteConnector(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.CONNECT)
    public List<ConnectInfo> connect(ConnectRequestDto request) throws ValidationException, ConnectException, ConnectorException {
        return connectorService.connect(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.RECONNECT)
    public ConnectInfo reconnect(UUID uuid) throws ValidationException, NotFoundException, ConnectException, ConnectorException {
        return connectorService.reconnect(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.APPROVE)
    public void approve(UUID uuid) throws NotFoundException, ValidationException {
        connectorService.approve(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.APPROVE)
    public List<BulkActionMessageDto> bulkApprove(List<UUID> uuids) throws NotFoundException, ValidationException {
        return connectorService.bulkApprove(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.RECONNECT)
    public List<BulkActionMessageDto> bulkReconnect(List<UUID> uuids) throws ValidationException, NotFoundException, ConnectException, ConnectorException {
        return connectorService.bulkReconnect(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteConnector(List<UUID> uuids) throws NotFoundException, ValidationException, ConnectorException {
        return connectorService.bulkDeleteConnector(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.FORCE_DELETE)
    public List<BulkActionMessageDto> bulkForceDeleteConnector(List<UUID> uuids) throws NotFoundException, ValidationException {
        return connectorService.forceDeleteConnector(SecuredUUID.fromUuidList(uuids));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.CHECK_HEALTH)
    public HealthInfo checkHealth(UUID uuid) throws NotFoundException, ConnectorException {
        return connectorService.checkHealth(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CONNECTOR, operation = Operation.GET_CONNECTOR_INFO)
    public ConnectorInfo getInfo(UUID uuid) throws NotFoundException, ConnectorException {
        return connectorService.getInfo(SecuredUUID.fromUUID(uuid));
    }
}
