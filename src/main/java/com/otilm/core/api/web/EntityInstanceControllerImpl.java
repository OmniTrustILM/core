package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.EntityInstanceController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.EntityInstanceResponseDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.entity.EntityInstanceRequestDto;
import com.otilm.api.model.client.entity.EntityInstanceUpdateRequestDto;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.entity.EntityInstanceDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.EntityInstanceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
public class EntityInstanceControllerImpl implements EntityInstanceController {

    @Autowired
    public void setEntityInstanceService(EntityInstanceExternalService entityInstanceService) {
        this.entityInstanceService = entityInstanceService;
    }

    private EntityInstanceExternalService entityInstanceService;

    @Override
    @AuthEndpoint(resourceName = Resource.ENTITY)
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ENTITY, operation = Operation.LIST)
    public EntityInstanceResponseDto listEntityInstances(final SearchRequestDto requestDto) {
        return entityInstanceService.listEntityInstances(SecurityFilter.create(), requestDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.ENTITY, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return entityInstanceService.getSearchableFieldInformationByGroup();
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ENTITY, operation = Operation.DETAIL)
    public EntityInstanceDto getEntityInstance(@LogResource(uuid = true) String entityUuid) throws ConnectorException, NotFoundException {
        return entityInstanceService.getEntityInstance(SecuredUUID.fromString(entityUuid));
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ENTITY, operation = Operation.CREATE)
    public ResponseEntity<?> createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        EntityInstanceDto entityInstance = entityInstanceService.createEntityInstance(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{entityUuid}")
                .buildAndExpand(entityInstance.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(entityInstance.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ENTITY, operation = Operation.UPDATE)
    public EntityInstanceDto editEntityInstance(@LogResource(uuid = true) String entityUuid, EntityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return entityInstanceService.editEntityInstance(SecuredUUID.fromString(entityUuid), request);
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ENTITY, operation = Operation.DELETE)
    public void deleteEntityInstance(@LogResource(uuid = true) String entityUuid) throws ConnectorException, NotFoundException {
        entityInstanceService.deleteEntityInstance(SecuredUUID.fromString(entityUuid));
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ATTRIBUTE, name = "location", affiliatedResource = Resource.ENTITY, operation = Operation.LIST_ATTRIBUTES)
    public List<BaseAttribute> listLocationAttributes(@LogResource(uuid = true, affiliated = true) String entityUuid) throws ConnectorException, NotFoundException {
        return entityInstanceService.listLocationAttributes(SecuredUUID.fromString(entityUuid));
    }

    @Override
    @AuditLogged(module = Module.ENTITIES, resource = Resource.ATTRIBUTE, name = "location", affiliatedResource = Resource.ENTITY, operation = Operation.VALIDATE_ATTRIBUTES)
    public void validateLocationAttributes(@LogResource(uuid = true, affiliated = true) String entityUuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        entityInstanceService.validateLocationAttributes(SecuredUUID.fromString(entityUuid), attributes);
    }
}
