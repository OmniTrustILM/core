package com.czertainly.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.GlobalMetadataController;
import com.otilm.api.model.client.attribute.AttributeDefinitionDto;
import com.otilm.api.model.client.attribute.metadata.*;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.AttributeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
public class GlobalMetadataControllerImpl implements GlobalMetadataController {

    private AttributeService attributeService;

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.LIST)
    public List<AttributeDefinitionDto> listGlobalMetadata() {
        return attributeService.listGlobalMetadata();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.DETAIL)
    public GlobalMetadataDefinitionDetailDto getGlobalMetadata(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return attributeService.getGlobalMetadata(UUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.CREATE)
    public ResponseEntity<GlobalMetadataDefinitionDetailDto> createGlobalMetadata(GlobalMetadataCreateRequestDto request) throws AlreadyExistException, AttributeException {
        GlobalMetadataDefinitionDetailDto definitionDetailDto = attributeService.createGlobalMetadata(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(definitionDetailDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(definitionDetailDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.UPDATE)
    public GlobalMetadataDefinitionDetailDto editGlobalMetadata(@LogResource(uuid = true) String uuid, GlobalMetadataUpdateRequestDto request) throws NotFoundException, AttributeException {
        return attributeService.editGlobalMetadata(UUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.DELETE)
    public void deleteGlobalMetadata(@LogResource(uuid = true) String uuid) throws NotFoundException {
        attributeService.demoteConnectorMetadata(UUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.DELETE)
    public void bulkDeleteGlobalMetadata(@LogResource(uuid = true) List<String> metadataUuids) {
        attributeService.bulkDemoteConnectorMetadata(metadataUuids);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.LIST)
    public List<ConnectorMetadataResponseDto> getConnectorMetadata(Optional<String> connectorUuid) {
        return attributeService.getConnectorMetadata(connectorUuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.GLOBAL_METADATA, operation = Operation.PROMOTE_METADATA)
    public GlobalMetadataDefinitionDetailDto promoteConnectorMetadata(ConnectorMetadataPromotionRequestDto request) throws NotFoundException {
        return attributeService.promoteConnectorMetadata(UUID.fromString(request.getUuid()), UUID.fromString(request.getConnectorUuid()));
    }
}
