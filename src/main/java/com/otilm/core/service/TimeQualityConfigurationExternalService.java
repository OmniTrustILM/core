package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface TimeQualityConfigurationExternalService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<TimeQualityConfigurationListDto> listTimeQualityConfigurations(SearchRequestDto request, SecurityFilter filter);

    TimeQualityConfigurationDto getTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException;

    TimeQualityConfigurationDto createTimeQualityConfiguration(TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    TimeQualityConfigurationDto updateTimeQualityConfiguration(SecuredUUID uuid, TimeQualityConfigurationRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    void deleteTimeQualityConfiguration(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteTimeQualityConfigurations(List<SecuredUUID> uuids);
}
