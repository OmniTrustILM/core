package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.core.model.signing.TspProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;

public interface TspProfileService extends ResourceExtensionService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<TspProfileListDto> listTspProfiles(SearchRequestDto request, SecurityFilter filter);

    TspProfileDto getTspProfile(SecuredUUID uuid) throws NotFoundException;

    TspProfileModel getTspProfile(String name) throws NotFoundException;

    TspProfileDto createTspProfile(TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    TspProfileDto updateTspProfile(SecuredUUID uuid, TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    void deleteTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteTspProfiles(List<SecuredUUID> uuids);

    void enableTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkEnableTspProfiles(List<SecuredUUID> uuids);

    void disableTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDisableTspProfiles(List<SecuredUUID> uuids);
}
