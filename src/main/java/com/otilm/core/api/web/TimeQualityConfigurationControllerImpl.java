package com.otilm.core.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.TimeQualityConfigurationController;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.auth.AuthEndpoint;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.TimeQualityConfigurationExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class TimeQualityConfigurationControllerImpl implements TimeQualityConfigurationController {

    private final TimeQualityConfigurationExternalService timeQualityConfigurationService;
    private final SigningProfileExternalService signingProfileService;

    @Autowired
    public TimeQualityConfigurationControllerImpl(TimeQualityConfigurationExternalService timeQualityConfigurationService,
                                                  SigningProfileExternalService signingProfileService) {
        this.timeQualityConfigurationService = timeQualityConfigurationService;
        this.signingProfileService = signingProfileService;
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
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, affiliatedResource = Resource.SIGNING_PROFILE, operation = Operation.LIST)
    public List<SimplifiedSigningProfileDto> listSigningProfilesForTimeQualityConfiguration(@LogResource(uuid = true) UUID uuid) {
        return signingProfileService.listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromUUID(uuid), SecurityFilter.create());
    }

    @Override
    @AuditLogged(module = Module.SIGNING, resource = Resource.TIME_QUALITY_CONFIGURATION, operation = Operation.DELETE)
    public List<BulkActionMessageDto> bulkDeleteTimeQualityConfigurations(@LogResource(uuid = true) List<UUID> uuids) {
        return timeQualityConfigurationService.bulkDeleteTimeQualityConfigurations(SecuredUUID.fromUuidList(uuids));
    }
}
