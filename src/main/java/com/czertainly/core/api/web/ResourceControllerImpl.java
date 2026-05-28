package com.czertainly.core.api.web;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.ResourceController;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.other.ResourceDto;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.other.ResourceEventDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.ResourceExternalService;
import com.czertainly.core.util.converter.ResourceCodeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class ResourceControllerImpl implements ResourceController {

    private ResourceExternalService resourceService;

    @Autowired
    public void setResourceService(ResourceExternalService resourceService) {
        this.resourceService = resourceService;
    }

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.RESOURCE, operation = Operation.LIST)
    public List<ResourceDto> listResources() {
        return resourceService.listResources();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.SEARCH_FILTER, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> listResourceRuleFilterFields(@LogResource(resource = true, affiliated = true) Resource resource, boolean settable) throws NotFoundException {
        return resourceService.listResourceRuleFilterFields(resource, settable);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.RESOURCE_EVENT, operation = Operation.LIST)
    public List<ResourceEventDto> listResourceEvents(@LogResource(resource = true, affiliated = true) Resource resource) {
        return resourceService.listResourceEvents(resource);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.RESOURCE_EVENT, operation = Operation.LIST)
    public Map<ResourceEvent, List<ResourceEventDto>> listAllResourceEvents() {
        return resourceService.listAllResourceEvents();
    }
}
