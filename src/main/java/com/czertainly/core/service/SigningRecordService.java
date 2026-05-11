package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordValidationResultDto;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.model.SecuredList;

import java.util.List;

public interface SigningRecordService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request, SecurityFilter filter);

    SecuredList<SigningRecord> listSigningRecordsAssociatedWithSigningProfile(SecuredUUID signingProfileUuid, SecurityFilter filter);

    SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException;

    SigningRecordValidationResultDto validateSigningRecord(SecuredUUID uuid) throws NotFoundException;

    void deleteSigningRecord(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteSigningRecords(List<SecuredUUID> uuids);
}
