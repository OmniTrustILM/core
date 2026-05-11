package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.TimeQualityConfigurationController;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.auth.AuthEndpoint;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TimeQualityConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class TimeQualityConfigurationControllerImpl implements TimeQualityConfigurationController {

    private final TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    public TimeQualityConfigurationControllerImpl(TimeQualityConfigurationService timeQualityConfigurationService) {
        this.timeQualityConfigurationService = timeQualityConfigurationService;
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.SEARCH_FILTER, affiliatedResource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return timeQualityConfigurationService.getSearchableFieldInformation();
    }

    @Override
    @AuthEndpoint(resourceName = Resource.TIME_QUALITY_CONFIGURATION)
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.LIST)
    public PaginationResponseDto<TimeQualityConfigurationListDto> listTimeQualityConfigurations(SearchRequestDto request) {
        return timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.DETAIL)
    public TimeQualityConfigurationDto getTimeQualityConfiguration(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        return timeQualityConfigurationService.getTimeQualityConfiguration(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.CREATE)
    public TimeQualityConfigurationDto createTimeQualityConfiguration(TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        return timeQualityConfigurationService.createTimeQualityConfiguration(request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.UPDATE)
    public TimeQualityConfigurationDto updateTimeQualityConfiguration(@LogResource(uuid = true) UUID uuid, TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException {
        return timeQualityConfigurationService.updateTimeQualityConfiguration(SecuredUUID.fromUUID(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.DELETE)
    public void deleteTimeQualityConfiguration(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        timeQualityConfigurationService.deleteTimeQualityConfiguration(SecuredUUID.fromUUID(uuid));
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteTimeQualityConfigurations(@LogResource(uuid = true) List<UUID> uuids) {
        return timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(SecuredUUID.fromUuidList(uuids));
    }
}
