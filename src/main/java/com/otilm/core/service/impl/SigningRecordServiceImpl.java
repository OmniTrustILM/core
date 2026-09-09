package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod.Bucket;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.ListingSortResolver;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.Audited_;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningProfileVersion_;
import com.otilm.core.dao.entity.signing.SigningProfile_;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.entity.signing.SigningRecordVolume_;
import com.otilm.core.dao.entity.signing.SigningRecord_;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.dao.repository.signing.SigningRecordVolumeRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.mapper.signing.SigningRecordMapper;
import com.otilm.core.mapper.workflows.PaginationResponseMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.SigningRecordInternalService;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class SigningRecordServiceImpl implements SigningRecordExternalService, SigningRecordInternalService {

    private static final String SIGNING_PROFILE_PARENT_REF = "signingProfileUuid";
    private static final int TOP_REQUESTERS = 10;
    private static final String SCHEME_PAIR_SEPARATOR = "::";

    /** Postgres {@code to_char} patterns producing the same key as {@link SigningRecordStatisticsCalculator}. */
    private static final String BUCKET_HOUR_FORMAT = "YYYY-MM-DD\"T\"HH24:00:00\"Z\"";
    private static final String BUCKET_DAY_FORMAT = "YYYY-MM-DD\"T\"00:00:00\"Z\"";

    private final SigningRecordRepository signingRecordRepository;
    private final SigningRecordVolumeRepository signingRecordVolumeRepository;
    private final SigningRecordWriter signingRecordWriter;
    private final SigningProfileRepository signingProfileRepository;
    private final AttributeEngine attributeEngine;
    private final AttributeColumnProjector attributeColumnProjector;
    private final ListingSortResolver listingSortResolver;
    private final AuthorizationEnforcer authorizationEnforcer;

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine
                .getResourceSearchableFields(Resource.SIGNING_RECORD, false);
        List<SearchFieldDataDto> fields = new ArrayList<>(List
                .of(SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_NAME),
                        SearchHelper
                                .prepareSearch(FilterField.SIGNING_RECORD_SIGNING_PROFILE,
                                        signingProfileRepository.findAllNames()),
                        SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_PROTOCOL),
                        SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION),
                        SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNING_TIME),
                        SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_SIGNED_DOCUMENT_RETRIEVED_AT),
                        SearchHelper.prepareSearch(FilterField.SIGNING_RECORD_CREATED)));
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));
        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecords(SearchRequestDto request,
            SecurityFilter filter) {
        return listRecords(request, filter, null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public PaginationResponseDto<SigningRecordListDto> listSigningRecordsForProfile(UUID signingProfileUuid,
            SearchRequestDto request, SecurityFilter filter) {
        return listRecords(request, filter, signingProfileUuid);
    }

    /**
     * Read under one snapshot: the signing figures are assembled from two tables, and a record deleted between the two
     * queries would otherwise be counted both as retained and as history. The transaction only reads, so the snapshot
     * cannot fail to serialize; it does hold the vacuum horizon for the length of the read.
     */
    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.LIST,
            parentResource = Resource.SIGNING_PROFILE, parentAction = ResourceAction.LIST)
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public SigningRecordStatisticsDto getSigningRecordStatistics(SigningRecordStatisticsPeriod period,
            SecurityFilter filter) {
        filter.setParentRefProperty(SIGNING_PROFILE_PARENT_REF);
        Instant now = Instant.now();

        SigningRecordStatisticsDto dto = new SigningRecordStatisticsDto();
        dto.setTotalRetained(signingRecordRepository.countUsingSecurityFilter(filter));
        dto.setCountLast24h(signingsSince(filter, now.minus(Duration.ofDays(1))));
        dto.setCountLast7d(signingsSince(filter, now.minus(Duration.ofDays(7))));

        Map<String, Long> byProfile = signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, SigningRecord_.signingProfile, SigningProfile_.name, null,
                        null);
        dto.setStatByProfile(byProfile);
        dto.setActiveProfileCount((long) byProfile.size());

        Map<String, Long> byRequester = signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, null, SigningRecord_.requestedByUsername, null, null);
        dto.setDistinctRequesterCount((long) byRequester.size());
        dto.setStatByRequester(SigningRecordStatisticsCalculator.topRequesters(byRequester, TOP_REQUESTERS));

        Map<String, Long> byWorkflow = signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, SigningRecord_.signingProfileVersionEntity,
                        SigningProfileVersion_.workflowType, null, null);
        dto.setStatByWorkflowType(byWorkflow);

        Map<String, Long> byProtocol = signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, null, SigningRecord_.protocol, null, null);
        dto.setStatByProtocol(byProtocol);
        dto.setStatByScheme(flattenSchemes(filter));

        dto.setVolumeOverTime(volumeOverTime(filter, period, now));
        return dto;
    }

    /**
     * Counts grouped by the flattened signing scheme, derived from the (scheme, managed type) pair on the profile
     * version.
     */
    private Map<String, Long> flattenSchemes(SecurityFilter filter) {
        Map<String, Long> bySchemePair = signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, null, null, this::signingSchemePairExpression, null);
        Map<String, Long> byScheme = new LinkedHashMap<>();
        bySchemePair.forEach((pair, count) -> {
            String[] parts = pair.split(SCHEME_PAIR_SEPARATOR, -1);
            if (parts.length != 2 || parts[0].isEmpty()) {
                return;
            }
            ManagedSigningType managedType = parts[1].isEmpty() ? null : ManagedSigningType.valueOf(parts[1]);
            byScheme
                    .merge(SigningRecordStatisticsCalculator
                            .flattenScheme(SigningScheme.valueOf(parts[0]), managedType), count, Long::sum);
        });
        return byScheme;
    }

    /**
     * {@code signing_scheme::managed_signing_type} (managed type blank for delegated), grouped on the joined profile
     * version.
     */
    private Expression<String> signingSchemePairExpression(Root<SigningRecord> root, CriteriaBuilder cb) {
        Join<SigningRecord, SigningProfileVersion> version = root
                .join(SigningRecord_.signingProfileVersionEntity, JoinType.LEFT);
        Expression<String> scheme = version.get(SigningProfileVersion_.signingScheme).as(String.class);
        Expression<String> managedType = cb
                .coalesce(version.get(SigningProfileVersion_.managedSigningType).as(String.class), "");
        return cb.concat(cb.concat(scheme, SCHEME_PAIR_SEPARATOR), managedType);
    }

    /**
     * The signing volume series: records still retained, plus the rolled-up counts of records already deleted. Both
     * halves are keyed identically, so summing them per bucket reconstructs what was signed regardless of what has
     * since been removed.
     */
    private Map<String, Long> volumeOverTime(SecurityFilter filter, SigningRecordStatisticsPeriod period, Instant now) {
        Instant from = windowStart(now.minus(period.getWindow()));
        Bucket bucket = period.getBucket();
        Map<String, Long> sparse = SigningRecordStatisticsCalculator
                .sumByBucket(retainedVolume(filter, bucket, from), deletedVolume(filter, bucket, from));
        return SigningRecordStatisticsCalculator.denseBuckets(from, now, bucket, sparse);
    }

    /** Signings performed since {@code cutoff}, whether or not their records still exist. */
    private Long signingsSince(SecurityFilter filter, Instant cutoff) {
        Instant from = windowStart(cutoff);
        long retained = signingRecordRepository.countUsingSecurityFilter(filter, signedSince(from));
        long deleted = deletedVolume(filter, Bucket.HOUR, from).values().stream().mapToLong(Long::longValue).sum();
        return retained + deleted;
    }

    /**
     * Start of the hour {@code cutoff} falls in. History is bucketed by the hour, so the retained half of a figure has
     * to start on the same boundary: only then does a signing contribute the same count before and after its record is
     * deleted. Against the exact cutoff, a signing in that first hour but before the cutoff would count for nothing
     * while retained and for one once deleted — deletion would raise the number.
     */
    private static Instant windowStart(Instant cutoff) {
        return cutoff.truncatedTo(ChronoUnit.HOURS);
    }

    private Map<String, Long> retainedVolume(SecurityFilter filter, Bucket bucket, Instant from) {
        return signingRecordRepository
                .countGroupedUsingSecurityFilter(filter, null, null,
                        (root, cb) -> bucketKey(cb, root.get(SigningRecord_.signingTime), bucket), signedSince(from));
    }

    /**
     * Bucketed counts of the records that have since been deleted. History is stored hourly, so a daily series sums
     * whole hours out of it. {@code from} is expected on an hour boundary; see {@link #windowStart}.
     */
    private Map<String, Long> deletedVolume(SecurityFilter filter, Bucket bucket, Instant from) {
        return signingRecordVolumeRepository
                .sumGroupedUsingSecurityFilter(signingProfileScope(filter), SigningRecordVolume_.signingCount,
                        (root, cb) -> bucketKey(cb, root.get(SigningRecordVolume_.bucketStart), bucket),
                        (root, cb, cq) -> cb.greaterThanOrEqualTo(root.get(SigningRecordVolume_.bucketStart), from));
    }

    /**
     * {@code to_char(date_trunc(unit, <instant> AT TIME ZONE 'UTC'), format)} — the canonical UTC bucket key of
     * {@link SigningRecordStatisticsCalculator#bucketKey}, expressed in SQL so both halves of the series key alike.
     */
    private static Expression<String> bucketKey(CriteriaBuilder cb, Expression<Instant> instant, Bucket bucket) {
        Expression<?> atUtc = cb.function("timezone", Timestamp.class, cb.literal("UTC"), instant);
        Expression<?> truncated = cb
                .function("date_trunc", Timestamp.class, cb.literal(bucket == Bucket.HOUR ? "hour" : "day"), atUtc);
        return cb
                .function("to_char", String.class, truncated,
                        cb.literal(bucket == Bucket.HOUR ? BUCKET_HOUR_FORMAT : BUCKET_DAY_FORMAT));
    }

    /**
     * The signing-profile half of {@code filter}. Signing-record visibility follows signing-profile access, and a
     * rolled-up bucket has no record identity left for a record-level filter to match on, so only the parent filter
     * carries over to the history rows. Nothing is lost with it while the authorization policy grants no object-level
     * access on signing records, which is what {@link Resource#SIGNING_RECORD} declaring none asks of it.
     */
    private static SecurityFilter signingProfileScope(SecurityFilter filter) {
        SecurityFilter scope = SecurityFilter.create();
        scope.setParentResourceFilter(filter.getParentResourceFilter());
        scope.setParentRefProperty(SIGNING_PROFILE_PARENT_REF);
        return scope;
    }

    private TriFunction<Root<SigningRecord>, CriteriaBuilder, CriteriaQuery<?>, Predicate> signedSince(Instant cutoff) {
        return (root, cb, cq) -> cb.greaterThanOrEqualTo(root.get(SigningRecord_.signingTime), cutoff);
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_RECORD, action = ResourceAction.DETAIL)
    @Transactional(readOnly = true)
    public SigningRecordDto getSigningRecord(SecuredUUID uuid) throws NotFoundException {
        SigningRecord signingRecord = getSigningRecordEntity(uuid);
        evaluateConnectedSigningProfileAccess(signingRecord);
        return SigningRecordMapper.toDto(signingRecord);
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

        for (SigningRecord signingRecord : records) {
            try {
                signingRecordWriter.deleteByUuid(signingRecord.getUuid());
            } catch (Exception e) {
                log.error("Failed to delete Signing Record {}", signingRecord.getUuid(), e);
                messages
                        .add(BulkActionMessageDto
                                .failure(signingRecord.getUuid().toString(), signingRecord.getName(), e,
                                        "Failed to delete signing record"));
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

    /**
     * Shared paginated listing for signing records, optionally scoped to a single signing profile when
     * {@code signingProfileUuid} is non-null.
     */
    private PaginationResponseDto<SigningRecordListDto> listRecords(SearchRequestDto request, SecurityFilter filter,
            UUID signingProfileUuid) {
        filter.setParentRefProperty(SIGNING_PROFILE_PARENT_REF);
        Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        TriFunction<Root<SigningRecord>, CriteriaBuilder, CriteriaQuery<?>, Predicate> predicate = (root, cb, cq) -> {
            Predicate filters = FilterPredicatesBuilder
                    .getFiltersPredicate(cb, cq, root, request.getFilters(), contentFilter);
            return signingProfileUuid == null
                    ? filters
                    : cb.and(cb.equal(root.get(SigningRecord_.signingProfileUuid), signingProfileUuid), filters);
        };
        List<SigningRecordListDto> dtos = signingRecordRepository
                .findUsingSecurityFilter(filter, List.of(), predicate, p,
                        (root, cb) -> cb.desc(root.get(Audited_.CREATED)),
                        listingSortResolver.resolve(Resource.SIGNING_RECORD, request.getSort(), contentFilter))
                .stream()
                .map(SigningRecordMapper::toListDto)
                .toList();
        attributeColumnProjector
                .project(Resource.SIGNING_RECORD, request.getColumns(), dtos,
                        signingRecord -> AttributeColumnProjector.parseUuid(signingRecord.getUuid()), contentFilter);

        long totalItems = signingRecordRepository.countUsingSecurityFilter(filter, predicate);
        return PaginationResponseMapper.toDto(dtos, request.getPageNumber(), request.getItemsPerPage(), totalItems);
    }

    private SigningRecord getSigningRecordEntity(SecuredUUID uuid) throws NotFoundException {
        return signingRecordRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException("Signing Record not found: " + uuid));
    }

    /**
     * Authorizes that the caller may access the signing profile the record was produced under, so signing-record
     * visibility follows signing-profile access.
     */
    private void evaluateConnectedSigningProfileAccess(SigningRecord signingRecord) {
        authorizationEnforcer
                .enforce(Resource.SIGNING_PROFILE, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(signingRecord.getSigningProfileUuid()));
    }

    /**
     * Authorizes the distinct signing profiles the records were produced under in a single check. All-or-nothing: if
     * access to any connected profile is denied, the whole batch is rejected.
     */
    private void evaluateConnectedSigningProfileAccess(List<SigningRecord> records) {
        List<SecuredUUID> signingProfileUuids = records
                .stream()
                .map(SigningRecord::getSigningProfileUuid)
                .distinct()
                .map(SecuredUUID::fromUUID)
                .toList();
        authorizationEnforcer.enforce(Resource.SIGNING_PROFILE, ResourceAction.DETAIL, signingProfileUuids);
    }
}
