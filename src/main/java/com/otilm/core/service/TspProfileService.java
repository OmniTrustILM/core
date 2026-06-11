package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;

public interface TspProfileService extends ResourceExtensionService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<TspProfileListDto> listTspProfiles(SearchRequestDto request, SecurityFilter filter);

    SecuredList<TspProfile> listTspProfilesUsingSigningProfileAsDefault(SecuredUUID signingProfileUuid, SecurityFilter filter);

    TspProfileDto getTspProfile(SecuredUUID uuid) throws NotFoundException;

    TspProfile getTspProfileEntity(SecuredUUID uuid) throws NotFoundException;

    List<String> findAllNames();

    TspProfileModel getTspProfile(String name) throws NotFoundException;

    TspProfileDto createTspProfile(TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    TspProfileDto updateTspProfile(SecuredUUID uuid, TspProfileRequestDto request) throws AlreadyExistException, AttributeException, NotFoundException;

    void deleteTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteTspProfiles(List<SecuredUUID> uuids);

    void enableTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkEnableTspProfiles(List<SecuredUUID> uuids);

    void disableTspProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDisableTspProfiles(List<SecuredUUID> uuids);

    /**
     * Clears every entry in the TSP profile cache.
     */
    void evictAllCachedModels();
}
