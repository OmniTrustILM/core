package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.CustomAttributeController;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeDefinitionDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeUpdateRequestDto;
import com.czertainly.api.model.common.attribute.common.AttributeContent;
import com.czertainly.api.model.common.attribute.common.CustomAttribute;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.AttributeService;
import com.czertainly.core.service.ResourceExternalService;
import com.czertainly.core.util.converter.AttributeContentTypeConverter;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@RestController
public class CustomAttributeControllerImpl implements CustomAttributeController {

    private AttributeService attributeService;
    private ResourceExternalService resourceService;

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setResourceService(ResourceExternalService resourceService) {
        this.resourceService = resourceService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
        webdataBinder.registerCustomEditor(AttributeContentType.class, new AttributeContentTypeConverter());
    }

    @Override
    @AuthEndpoint(resourceName = Resource.ATTRIBUTE)
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.LIST)
    public List<CustomAttributeDefinitionDto> listCustomAttributes(AttributeContentType attributeContentType) {
        return attributeService.listCustomAttributes(SecurityFilter.create(), attributeContentType);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DETAIL)
    public CustomAttributeDefinitionDetailDto getCustomAttribute(@LogResource(uuid = true) String uuid) throws NotFoundException {
        return attributeService.getCustomAttribute(UUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.CREATE)
    public ResponseEntity<CustomAttributeDefinitionDetailDto> createCustomAttribute(CustomAttributeCreateRequestDto request) throws AlreadyExistException, AttributeException {
        CustomAttributeDefinitionDetailDto definitionDetailDto = attributeService.createCustomAttribute(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(definitionDetailDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(definitionDetailDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.UPDATE)
    public CustomAttributeDefinitionDetailDto editCustomAttribute(@LogResource(uuid = true) String uuid, CustomAttributeUpdateRequestDto request) throws NotFoundException, AttributeException {
        return attributeService.editCustomAttribute(UUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DELETE)
    public void deleteCustomAttribute(@LogResource(uuid = true) String uuid) throws NotFoundException {
        attributeService.deleteCustomAttribute(UUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.ENABLE)
    public void enableCustomAttribute(@LogResource(uuid = true) String uuid) throws NotFoundException {
        attributeService.enableCustomAttribute(UUID.fromString(uuid), true);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DISABLE)
    public void disableCustomAttribute(@LogResource(uuid = true) String uuid) throws NotFoundException {
        attributeService.enableCustomAttribute(UUID.fromString(uuid), false);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DELETE)
    public void bulkDeleteCustomAttributes(@LogResource(uuid = true) List<String> attributeUuids) {
        attributeService.bulkDeleteCustomAttributes(attributeUuids);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.ENABLE)
    public void bulkEnableCustomAttributes(@LogResource(uuid = true) List<String> attributeUuids) {
        attributeService.bulkEnableCustomAttributes(attributeUuids, true);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DISABLE)
    public void bulkDisableCustomAttributes(@LogResource(uuid = true) List<String> attributeUuids) {
        attributeService.bulkEnableCustomAttributes(attributeUuids, false);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.UPDATE_ATTRIBUTE_RESOURCES)
    public void updateResources(@LogResource(uuid = true) String uuid, List<Resource> resources) throws NotFoundException {
        attributeService.updateResources(UUID.fromString(uuid), resources);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.LIST)
    public List<CustomAttribute> getResourceCustomAttributes(@LogResource(resource = true, affiliated = true) Resource resource) {
        return attributeService.getResourceAttributes(SecurityFilter.create(), resource);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.RESOURCE, affiliatedResource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.LIST)
    public List<Resource> getResources() {
        return attributeService.getResources();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.UPDATE_ATTRIBUTE_CONTENT)
    public List<ResponseAttribute> updateAttributeContentForResource(
            @LogResource(resource = true, affiliated = true) Resource resourceName,
            @LogResource(uuid = true, affiliated = true) String objectUuid,
            @LogResource(uuid = true) String attributeUuid,
            List<AttributeContent> request
    ) throws NotFoundException, AttributeException {
        return resourceService.updateAttributeContentForObject(
                SecuredResource.fromResource(resourceName),
                SecuredUUID.fromString(objectUuid),
                UUID.fromString(attributeUuid),
                request
        );
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.CUSTOM_ATTRIBUTE, operation = Operation.DELETE_ATTRIBUTE_CONTENT)
    public List<ResponseAttribute> deleteAttributeContentForResource(
            @LogResource(resource = true, affiliated = true) Resource resourceName,
            @LogResource(uuid = true, affiliated = true) String objectUuid,
            @LogResource(uuid = true) String attributeUuid
    ) throws NotFoundException, AttributeException {
        return resourceService.updateAttributeContentForObject(
                SecuredResource.fromResource(resourceName),
                SecuredUUID.fromString(objectUuid),
                UUID.fromString(attributeUuid),
                null
        );
    }
}
