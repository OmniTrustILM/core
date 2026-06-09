package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface SigningRecordService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request, SecurityFilter filter);

    SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException;

    void deleteSigningRecord(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteSigningRecords(List<SecuredUUID> uuids);

    boolean doesSigningRecordExistInternal(UUID uuid, int version);

    boolean doesSigningRecordExistForProfileInternal(UUID signingProfileUuid);
}
