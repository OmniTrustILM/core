package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Audited_;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.mapper.signing.SigningRecordMapper;
import com.czertainly.core.mapper.workflows.PaginationResponseMapper;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.util.SearchHelper;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.PermissionEvaluator;
import com.czertainly.core.service.SigningRecordService;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
import com.czertainly.core.util.FilterPredicatesBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
public class SigningRecordServiceImpl implements SigningRecordService {

    private final SigningRecordRepository signingRecordRepository;
    private final SigningRecordWriter signingRecordWriter;
    private final SigningProfileRepository signingProfileRepository;
    private final AttributeEngine attributeEngine;
    private final PermissionEvaluator permissionEvaluator;

    public SigningRecordServiceImpl(SigningRecordRepository signingRecordRepository,
                                    SigningRecordWriter signingRecordWriter,
                                    SigningProfileRepository signingProfileRepository,
                                    AttributeEngine attributeEngine,
                                    PermissionEvaluator permissionEvaluator) {
        this.signingRecordRepository = signingRecordRepository;
        this.signingRecordWriter = signingRecordWriter;
        this.signingProfileRepository = signingProfileRepository;
        this.attributeEngine = attributeEngine;
        this.permissionEvaluator = permissionEvaluator;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.SIGNING_RECORD, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List.of(
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_NAME),
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNING_PROFILE, signingProfileRepository.findAllNames()),
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION),
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNING_TIME),
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNED_DOCUMENT_RETRIEVED_AT),
                SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_CREATED)
        ));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST, parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request, SecurityFilter filter) {
        filter.setParentRefProperty("signingProfileUuid");
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        TriFunction<Root<SigningRecord>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate =
                (root, cb, cq) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cq, root, request.getFilters());
        List<SigningRecordListDto> dtos = signingRecordRepository.findUsingSecurityFilter(filter, List.of(), predicate, p,
                        (root, cb) -> cb.desc(root.get(Audited_.CREATED)))
                .stream().map(SigningRecordMapper::toListDto).toList();
        long totalItems = signingRecordRepository.countUsingSecurityFilter(filter, predicate);
        return PaginationResponseMapper.toDto(dtos, request.getPageNumber(), request.getItemsPerPage(), totalItems);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException {
        SigningRecord record = getSigningRecordEntity(uuid);
        evaluateConnectedSigningProfileAccess(record);
        return SigningRecordMapper.toDto(record);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DELETE)
    public void deleteSigningRecord(SecuredUUID uuid) throws NotFoundException {
        SigningRecord signingRecord = getSigningRecordEntity(uuid);
        evaluateConnectedSigningProfileAccess(signingRecord);
        signingRecordWriter.deleteByUuid(signingRecord.getUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteSigningRecords(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        List<SigningRecord> records = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            try {
                records.add(getSigningRecordEntity(uuid));
            } catch (Exception e) {
                log.error("Failed to delete Signing Record {}", uuid, e);
                messages.add(BulkActionMessageDto.failure(uuid.toString(), "", e, "Failed to delete signing record"));
            }
        }
        if (records.isEmpty()) {
            return messages;
        }
        evaluateConnectedSigningProfileAccess(records);

        for (SigningRecord record : records) {
            try {
                signingRecordWriter.deleteByUuid(record.getUuid());
            } catch (Exception e) {
                log.error("Failed to delete Signing Record {}", record.getUuid(), e);
                messages.add(BulkActionMessageDto.failure(record.getUuid().toString(), record.getName(), e, "Failed to delete signing record"));
            }
        }
        return messages;
    }

    @Override
    public boolean doesSigningRecordExistInternal(UUID uuid, int version) {
        return signingRecordRepository.existsBySigningProfileUuidAndSigningProfileVersion(uuid, version);
    }

    @Override
    public boolean doesSigningRecordExistForProfileInternal(UUID signingProfileUuid) {
        return signingRecordRepository.existsBySigningProfileUuid(signingProfileUuid);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    private SigningRecord getSigningRecordEntity(SecuredUUID uuid) throws NotFoundException {
        return signingRecordRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException("Signing Record not found: " + uuid));
    }

    /**
     * Authorizes that the caller may access the signing profile the record was produced under,
     * so signing-record visibility follows signing-profile access.
     */
    private void evaluateConnectedSigningProfileAccess(SigningRecord record) throws NotFoundException {
        permissionEvaluator.signingProfile(SecuredUUID.fromUUID(record.getSigningProfileUuid()));
    }

    /**
     * Authorizes the distinct signing profiles the records were produced under in a single check.
     * All-or-nothing: if access to any connected profile is denied, the whole batch is rejected.
     */
    private void evaluateConnectedSigningProfileAccess(List<SigningRecord> records) {
        List<SecuredUUID> signingProfileUuids = records.stream()
                .map(SigningRecord::getSigningProfileUuid)
                .distinct()
                .map(SecuredUUID::fromUUID)
                .toList();
        permissionEvaluator.signingProfiles(signingProfileUuids);
    }
}
