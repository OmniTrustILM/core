package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface TimeQualityConfigurationService extends ResourceExtensionService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<TimeQualityConfigurationListDto> listTimeQualityConfigurations(SearchRequestDto request, SecurityFilter filter);

    TimeQualityConfigurationDto getTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException;

    TimeQualityConfigurationDto createTimeQualityConfiguration(TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    TimeQualityConfigurationDto updateTimeQualityConfiguration(SecuredUUID uuid, TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    void deleteTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteTimeQualityConfigurations(List<SecuredUUID> uuids);
}
