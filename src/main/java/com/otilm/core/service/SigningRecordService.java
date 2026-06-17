package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.UUID;

public interface SigningRecordService {

    List<SearchFieldDataByGroupDto> getSearchableFieldInformation();

    PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request, SecurityFilter filter);

    /**
     * Lists signing records scoped to a single signing profile. Authorized independently as a
     * {@code SIGNING_RECORD/LIST} operation (with row-level access delegated to the parent signing
     * profile as {@code SIGNING_PROFILE/DETAIL}, matching the single-record paths), so signing-record
     * visibility is required even when reached via a profile-scoped endpoint.
     */
    PaginationResponseDto<SigningRecordListDto> listSigningRecordsForProfile(UUID signingProfileUuid, SearchRequestDto request, SecurityFilter filter);

    /**
     * Computes the Signing Records dashboard statistics from the shared {@code signing_record} table, scoped to the
     * signing profiles the caller may access. Only the volume-over-time series depends on {@code period}; the badge
     * counts and breakdown maps are window-independent.
     */
    SigningRecordStatisticsDto getSigningRecordStatistics(SigningRecordStatisticsPeriod period, SecurityFilter filter);

    SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException;

    void deleteSigningRecord(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteSigningRecords(List<SecuredUUID> uuids);

    boolean doesSigningRecordExistInternal(UUID uuid, int version);

    boolean doesSigningRecordExistForProfileInternal(UUID signingProfileUuid);
}
