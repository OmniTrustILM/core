package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordValidationResultDto;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.mapper.signing.SigningRecordMapper;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SigningRecordService;
import com.czertainly.core.service.model.SecuredList;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class SigningRecordServiceImpl implements SigningRecordService {

    private SigningRecordRepository signingRecordRepository;
    private SigningRecordServiceImpl self;

    @Autowired
    public void setSigningRecordRepository(SigningRecordRepository signingRecordRepository) {
        this.signingRecordRepository = signingRecordRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        return new ArrayList<>();
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request, SecurityFilter filter) {
        List<SigningRecord> records = signingRecordRepository.findUsingSecurityFilter(filter);
        List<SigningRecordListDto> dtos = records.stream()
                .map(SigningRecordMapper::toListDto)
                .toList();
        PaginationResponseDto<SigningRecordListDto> response = new PaginationResponseDto<>();
        // :TODO: this is completely wrong
        response.setItemsPerPage(dtos.size());
        response.setPageNumber(1);
        response.setTotalItems(dtos.size());
        response.setTotalPages(1);
        response.setItems(dtos);
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SecuredList<SigningRecord> listSigningRecordsAssociatedWithSigningProfile(SecuredUUID signingProfileUuid, SecurityFilter filter) {
        List<SigningRecord> records = signingRecordRepository.findAllBySigningProfileUuid(signingProfileUuid.getValue());
        return SecuredList.fromFilter(filter, records);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException {
        SigningRecord record = getSigningRecordEntity(uuid);
        return SigningRecordMapper.toDto(record);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningRecordValidationResultDto validateSigningRecord(SecuredUUID uuid) throws NotFoundException {
        getSigningRecord(uuid);
        throw new UnsupportedOperationException("Signing record validation not yet implemented");
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DELETE)
    @Transactional
    public void deleteSigningRecord(SecuredUUID uuid) throws NotFoundException {
        SigningRecord signingRecord = getSigningRecordEntity(uuid);
        signingRecordRepository.delete(signingRecord);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteSigningRecords(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            SigningRecord signingRecord = null;
            try {
                signingRecord = getSigningRecordEntity(uuid);
                self.deleteInOwnTransaction(signingRecord);
            } catch (Exception e) {
                log.error("Failed to delete Time Quality Configuration {}", uuid, e);
                messages.add(new BulkActionMessageDto(uuid.toString(), signingRecord != null ? signingRecord.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void deleteInOwnTransaction(SigningRecord signingRecord) {
        signingRecordRepository.delete(signingRecord);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private SigningRecord getSigningRecordEntity(SecuredUUID uuid) throws NotFoundException {
        return signingRecordRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException("Signing Record not found: " + uuid));
    }

    @Lazy
    @Autowired
    public void setSelf(SigningRecordServiceImpl self) {
        this.self = self;
    }
}
