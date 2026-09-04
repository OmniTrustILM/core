package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetEvidenceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetNormalizedFieldsDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetOidDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetSourceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetVerdictDto;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.Cbom_;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource_;
import com.otilm.core.dao.entity.cbom.CryptoAsset_;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.model.cbom.CryptoAssetListRow;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ObjectFilterAspect;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.stereotype.Service;

/**
 * Serves the ratified cryptographic asset inventory contract: list, detail, searchable-fields and the dashboard
 * statistics are all real reads over the deduplicated cross-CBOM asset projection. The service also serves the
 * per-object listing behind {@code @AuthEndpoint} -- the role editor's object picker.
 */
@Service(Resource.Codes.CRYPTO_ASSET)
@Slf4j
public class CryptographicAssetServiceImpl implements CryptographicAssetExternalService, ResourceExtensionService {

    /** Top-N cap on the served algorithm-family distribution; the badge pair carries the overflow. */
    private static final int TOP_ALGORITHM_FAMILIES = 10;

    // Per-source evidence is already bounded at 50 occurrences / 64KB by OccurrenceEvidenceCapper; the asset-level
    // fan-out -- one row per contributing CBOM -- is not. 100 x ~70KB bounds the response while sourceCbomCount
    // keeps carrying the true total, the same served-vs-true pattern occurrenceCount already uses.
    private static final int MAX_SERVED_SOURCES = 100;

    // The OpenAPI schema documents 1000 as the maximum items per page; this is where it is actually enforced.
    private static final int MAX_ITEMS_PER_PAGE = 1000;

    private CryptoAssetRepository cryptoAssetRepository;

    private CryptoAssetSourceRepository cryptoAssetSourceRepository;

    private CbomRepository cbomRepository;

    private ObjectFilterAspect objectFilterAspect;

    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCryptoAssetRepository(CryptoAssetRepository cryptoAssetRepository) {
        this.cryptoAssetRepository = cryptoAssetRepository;
    }

    @Autowired
    public void setCryptoAssetSourceRepository(CryptoAssetSourceRepository cryptoAssetSourceRepository) {
        this.cryptoAssetSourceRepository = cryptoAssetSourceRepository;
    }

    @Autowired
    public void setCbomRepository(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
    }

    @Autowired
    public void setObjectFilterAspect(ObjectFilterAspect objectFilterAspect) {
        this.objectFilterAspect = objectFilterAspect;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.LIST)
    public PaginationResponseDto<CryptographicAssetDto> listCryptographicAssets(SecurityFilter filter,
            SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        validatePaging(request);
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        TriFunction<Root<CryptoAsset>, CriteriaBuilder, CriteriaQuery<?>, Predicate> where = (root, cb,
                criteriaQuery) -> FilterPredicatesBuilder
                        .getFiltersPredicate(cb, criteriaQuery, root, request.getFilters(), contentFilter);
        Pageable page = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        // The contract's "ordered by name ascending" means the SERVED name -- displayLabel's guarded coalesce --
        // not the bare column, which would sort every oid-served row after the named ones (NULL sorts last).
        // Only this term is spelled here: the repository appends the ascending-uuid tiebreak to every paged
        // secured query (SortOrderBuilder), which keeps page boundaries deterministic inside equal labels.
        List<UUID> pageUuids = cryptoAssetRepository
                .findUuidsUsingSecurityFilter(filter, where, page, (root, cb) -> cb.asc(displayLabel(root, cb)));
        // The plain-count variant: every crypto-asset predicate is either single-column or an EXISTS subquery and
        // the resource declares no groups or owner, so no query shape can duplicate a root row -- and
        // count(DISTINCT) forfeits parallel aggregation, which at millions of rows is seconds per page request.
        long totalItems = cryptoAssetRepository.countRowsUsingSecurityFilter(filter, where);
        PaginationResponseDto<CryptographicAssetDto> response = new PaginationResponseDto<>();
        response.setItems(loadPage(pageUuids));
        response.setItemsPerPage(request.getItemsPerPage());
        response.setPageNumber(request.getPageNumber());
        response.setTotalItems(totalItems);
        response.setTotalPages((int) Math.ceil((double) totalItems / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.DETAIL)
    public CryptographicAssetDetailDto getCryptographicAsset(SecuredUUID uuid) throws NotFoundException {
        CryptoAsset asset = cryptoAssetRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptoAsset.class, uuid));
        List<CryptoAssetSource> sources = cryptoAssetSourceRepository.findWithCbomByAssetUuid(asset.getUuid());
        return toDetailDto(asset, sources, visibleCbomUuids(asset.getUuid()));
    }

    /**
     * The CBOM documents whose content the caller may read, scoped by the caller's own {@code cboms:list} object access
     * -- serial numbers and payloads belong to the CBOM resource, the same rule
     * {@link #cbomSerialNumbersScopedToCaller} applies to the source-CBOM value list. Narrowed to the documents that
     * actually contribute to this asset, mirroring {@link #hasContributedAssets}, so the EXISTS subquery stays cheap.
     */
    private Set<UUID> visibleCbomUuids(UUID assetUuid) {
        SecurityFilter cbomFilter = SecurityFilter.create();
        objectFilterAspect.populateSecurityFilter(Resource.CBOM, ResourceAction.LIST, null, null, cbomFilter);
        // Unpaged: Pageable.unpaged() throws from window()'s getOffset()/getPageSize(), unsupported on that
        // sentinel. A null Pageable and null order is this codebase's own idiom for "every matching uuid, no
        // paging, no particular order" -- see CryptographicKeyServiceImpl#filterKeyItemsBySecurityFilter and
        // CertificateServiceImpl#bulkDeleteCertificateBatch.
        return new HashSet<>(
                cbomRepository.findUuidsUsingSecurityFilter(cbomFilter, contributesToAsset(assetUuid), null, null));
    }

    /**
     * {@link #hasContributedAssets}, narrowed to one asset: the EXISTS subquery a per-detail visibility scope needs.
     */
    private static TriFunction<Root<Cbom>, CriteriaBuilder, CriteriaQuery<?>, Predicate> contributesToAsset(
            UUID assetUuid) {
        return (root, cb, query) -> {
            Subquery<Integer> contributed = query.subquery(Integer.class);
            Root<CryptoAssetSource> source = contributed.from(CryptoAssetSource.class);
            contributed
                    .select(cb.literal(1))
                    .where(cb.equal(source.get(CryptoAssetSource_.cbomUuid), root.get(UniquelyIdentified_.uuid)),
                            cb.equal(source.get(CryptoAssetSource_.assetUuid), assetUuid));
            return cb.exists(contributed);
        };
    }

    /**
     * The group is PROPERTY only: crypto assets carry no attribute-engine attributes, so offering CUSTOM/META groups
     * would advertise filter sources this resource does not serve. Curve values are the distinct stored spellings of
     * the normalized column -- one entry per stored token; they become the ratified class representatives once
     * core#2072's ingest canonicalization writes them (see the value-list queries' javadoc). The enum-backed and
     * boolean fields get their values from {@link SearchHelper} (enum codes, or none).
     */
    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        List<SearchFieldDataDto> fields = List
                .of(SearchHelper.prepareSearch(FilterField.CBOM_ASSET_FREE_TEXT),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_TYPE),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_NAME),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_OID),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_OID_REFUTED),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_ALGORITHM_FAMILY,
                                        cryptoAssetRepository.findDistinctAlgorithmFamily()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_PRIMITIVE,
                                        cryptoAssetRepository.findDistinctPrimitive()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_PARAMETER_SET,
                                        cryptoAssetRepository.findDistinctParameterSet()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_CURVE, cryptoAssetRepository.findDistinctCurve()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_MODE, cryptoAssetRepository.findDistinctMode()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_PADDING,
                                        cryptoAssetRepository.findDistinctPadding()),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_VARIANT,
                                        cryptoAssetRepository.findDistinctVariant()),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_PQC_VERDICT),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_PQC_RULESET_VERSION),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_RULESET_VERSION),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSET_SOURCE_COUNT), SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_SOURCE_CBOM, cbomSerialNumbersScopedToCaller()));
        List<SearchFieldDataDto> sorted = new ArrayList<>(fields);
        sorted.sort(new SearchFieldDataComparator());
        return List.of(new SearchFieldDataByGroupDto(sorted, FilterFieldSource.PROPERTY));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.LIST)
    public CryptographicAssetStatisticsDto getCryptographicAssetStatistics(SecurityFilter filter) {
        // The annotation aspect populates `filter` under the caller's CRYPTO_ASSET LIST scope before this method
        // runs -- the same mechanism listCryptographicAssets uses -- which is what makes these numbers reconcile
        // with the list. The document-level completeness block is a second, cross-resource scope the aspect
        // cannot populate from one annotation, so only that half is still built by hand, same as
        // cbomSerialNumbersScopedToCaller and the detail endpoint's visibleCbomUuids.
        SecurityFilter cbomFilter = SecurityFilter.create();
        objectFilterAspect.populateSecurityFilter(Resource.CBOM, ResourceAction.LIST, null, null, cbomFilter);
        long start = System.nanoTime();
        try (ExecutorService executor = new DelegatingSecurityContextExecutorService(
                Executors.newVirtualThreadPerTaskExecutor())) {
            Future<Long> totalAssets = executor
                    .submit(() -> cryptoAssetRepository.countRowsUsingSecurityFilter(filter, null));
            Future<Map<String, Long>> byType = executor
                    .submit(() -> cryptoAssetRepository
                            .countGroupedUsingSecurityFilter(filter, null, CryptoAsset_.assetType, null, null));
            Future<Map<String, Long>> byVerdict = executor
                    .submit(() -> cryptoAssetRepository
                            .countGroupedUsingSecurityFilter(filter, null, CryptoAsset_.pqcVerdict, null, null));
            Future<Map<String, Long>> byFamily = executor
                    .submit(() -> cryptoAssetRepository
                            .countGroupedUsingSecurityFilter(filter, null, CryptoAsset_.algorithmFamily, null, null));
            Future<Long> sourceCbomCount = executor
                    .submit(() -> cbomRepository
                            .countUsingSecurityFilter(cbomFilter, CryptographicAssetServiceImpl::hasContributedAssets));
            Future<Map<String, Long>> bySyncState = executor
                    .submit(() -> cbomRepository
                            .countGroupedUsingSecurityFilter(cbomFilter, null, Cbom_.assetSyncState, null, null));
            Future<OffsetDateTime> lastCompletedSyncAt = executor.submit(() -> lastCompletedSyncAt(cbomFilter));
            CryptographicAssetStatisticsDto dto = CryptographicAssetStatisticsCalculator
                    .assemble(totalAssets.get(), byType.get(), byVerdict.get(), byFamily.get(), TOP_ALGORITHM_FAMILIES,
                            sourceCbomCount.get(), bySyncState.get(), lastCompletedSyncAt.get());
            if (deniesEverything(cbomFilter)) {
                // A permission-shaped zero reads as "nothing has ever synced"; omitting the document-derived block
                // instead states plainly that access, not the estate, is why nothing is served. Asset-side
                // statistics above are untouched -- they are scoped by the independent CRYPTO_ASSET gate.
                dto.setSourceCbomCount(null);
                dto.setSyncCompleteness(null);
            }
            log.debug("Cryptographic asset statistics calculated in {} ms", (System.nanoTime() - start) / 1_000_000L);
            return dto;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Cryptographic asset statistics aggregation was interrupted", e);
        } catch (ExecutionException e) {
            // Unlike the mixed dashboard, this endpoint serves one resource: a failed aggregate must fail the
            // request rather than silently serve zeros that no longer reconcile with the list.
            throw new IllegalStateException("Cryptographic asset statistics aggregation failed", e.getCause());
        }
    }

    /**
     * Whether the populated filter denies every object of its resource outright: {@code areOnlySpecificObjectsAllowed}
     * true with an empty allow-list -- the shape {@code ObjectFilterAspect#getResourceFilter} builds from an OPA "not
     * allowed for the whole group of objects" vote that also names no individually allowed uuid, which is what
     * {@code BaseSpringBootTest.denyObjectAccess} stubs. A partial restriction (some uuids allowed, or the whole group
     * allowed with some forbidden) does not match this and keeps serving scoped counts as before.
     */
    private static boolean deniesEverything(SecurityFilter filter) {
        SecurityResourceFilter resourceFilter = filter.getResourceFilter();
        return resourceFilter != null && resourceFilter.areOnlySpecificObjectsAllowed()
                && resourceFilter.getAllowedObjects().isEmpty();
    }

    /** A document contributed to the inventory when at least one asset-source row points at it. */
    private static Predicate hasContributedAssets(Root<Cbom> root, CriteriaBuilder cb, CriteriaQuery<?> query) {
        Subquery<Integer> contributed = query.subquery(Integer.class);
        Root<CryptoAssetSource> source = contributed.from(CryptoAssetSource.class);
        contributed
                .select(cb.literal(1))
                .where(cb.equal(source.get(CryptoAssetSource_.cbomUuid), root.get(UniquelyIdentified_.uuid)));
        return cb.exists(contributed);
    }

    private OffsetDateTime lastCompletedSyncAt(SecurityFilter cbomFilter) {
        List<UUID> newest = cbomRepository
                .findUuidsUsingSecurityFilter(cbomFilter,
                        (root, cb, query) -> cb.isNotNull(root.get(Cbom_.assetsSyncedAt)), PageRequest.of(0, 1),
                        (root, cb) -> cb.desc(root.get(Cbom_.assetsSyncedAt)));
        if (newest.isEmpty()) {
            return null;
        }
        return cbomRepository.findById(newest.getFirst()).map(Cbom::getAssetsSyncedAt).orElse(null);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return cryptoAssetRepository.findResourceObject(objectUuid, CryptographicAssetServiceImpl::displayLabel);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return cryptoAssetRepository
                .findResourceObject(objectUuid.getValue(), CryptographicAssetServiceImpl::displayLabel);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        // A search typed into the role editor's picker arrives as filters; honour them the way the inventory list
        // does (the entity-instance extension is the platform's filter-honouring precedent).
        TriFunction<Root<CryptoAsset>, CriteriaBuilder, CriteriaQuery<?>, Predicate> where = filters == null
                || filters.isEmpty()
                        ? null
                        : (root, cb, criteriaQuery) -> FilterPredicatesBuilder
                                .getFiltersPredicate(cb, criteriaQuery, root, filters, contentFilter);
        return cryptoAssetRepository
                .listResourceObjects(filter, CryptographicAssetServiceImpl::displayLabel, where, pagination);
    }

    // DETAIL is this resource's own object-read gate, and it has no parent resource to chain through. Sibling
    // extension services gate this with UPDATE because their one generic caller writes attribute content; that
    // caller is unreachable here while hasCustomAttributes stays false, and DETAIL avoids syncing a spurious
    // update action onto a read-only resource -- if custom attributes are ever enabled, this must become UPDATE.
    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.DETAIL)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        cryptoAssetRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(CryptoAsset.class, uuid));
    }

    private static void validatePaging(SearchRequestDto request) {
        // No crypto-asset field is marked sortable, and the contract permits sorting only on fields marked sortable.
        if (request.getSort() != null) {
            throw new ValidationException(
                    "Sorting is not supported for the cryptographic asset inventory; results are ordered by name, then UUID.");
        }
        // PageRequest would otherwise turn an out-of-range value into a 500 rather than a shaped 422.
        if (request.getPageNumber() < 1) {
            throw new ValidationException("Page number must be at least 1, but was " + request.getPageNumber());
        }
        if (request.getItemsPerPage() < 1) {
            throw new ValidationException("Items per page must be at least 1, but was " + request.getItemsPerPage());
        }
        if (request.getItemsPerPage() > MAX_ITEMS_PER_PAGE) {
            request.setItemsPerPage(MAX_ITEMS_PER_PAGE);
        }
        // The JPA offset is an int. An unchecked (pageNumber - 1) * itemsPerPage either throws deep in Hibernate
        // (a 400, not the shaped 422) or -- worse -- wraps positive and silently serves the wrong page while
        // echoing the requested page number.
        if ((long) (request.getPageNumber() - 1) * request.getItemsPerPage() > Integer.MAX_VALUE) {
            throw new ValidationException("Page number " + request.getPageNumber() + " with "
                    + request.getItemsPerPage() + " items per page exceeds the addressable offset.");
        }
    }

    /**
     * The source-CBOM value list crosses a resource gate -- serial numbers belong to the CBOM resource, and every other
     * platform value list stays inside its own resource's table. So this one is scoped by the caller's own
     * {@code cboms:list} object access, populated the same way the rule-filter-fields listing scopes its field
     * resources: a caller without CBOM access gets an empty value list (the filter itself keeps working by hand), never
     * the platform's whole document inventory.
     */
    private List<String> cbomSerialNumbersScopedToCaller() {
        SecurityFilter cbomFilter = SecurityFilter.create();
        objectFilterAspect.populateSecurityFilter(Resource.CBOM, ResourceAction.LIST, null, null, cbomFilter);
        return cbomRepository
                .countGroupedUsingSecurityFilter(cbomFilter, null, Cbom_.serialNumber, null, null)
                .keySet()
                .stream()
                .sorted()
                .toList();
    }

    private List<CryptographicAssetDto> loadPage(List<UUID> pageUuids) {
        if (pageUuids.isEmpty()) {
            return List.of();
        }
        Map<UUID, CryptoAssetListRow> rowsByUuid = cryptoAssetRepository
                .findListRowsByUuids(pageUuids)
                .stream()
                .collect(Collectors.toMap(CryptoAssetListRow::uuid, Function.identity()));
        return pageUuids
                .stream()
                // A uuid whose row vanished between the page and projection queries is skipped rather than failed.
                .map(rowsByUuid::get)
                .filter(Objects::nonNull)
                .map(CryptographicAssetServiceImpl::toDto)
                .collect(Collectors.toList());
    }

    /**
     * The display label, everywhere one is served: the list's {@code name}, the picker's label, and the list order. The
     * producer name, else the recorded OID -- EXCEPT a {@code REFUTED_OID} row, whose OID must never be presented as
     * fact: the refuted ruling's principle is that a client labels such a value instead of serving it bare, and neither
     * this DTO nor the picker's carries a flag to label it with. Must stay in lock-step with {@link #servedName}, its
     * in-memory twin.
     */
    private static Expression<String> displayLabel(Root<CryptoAsset> root, CriteriaBuilder cb) {
        Expression<String> oidUnlessRefuted = cb
                .<String>selectCase()
                .when(cb.equal(root.get(CryptoAsset_.identityGuard), CryptoAssetIdentityGuard.REFUTED_OID),
                        cb.nullLiteral(String.class))
                .otherwise(root.get(CryptoAsset_.oid));
        return cb.coalesce(root.get(CryptoAsset_.name), oidUnlessRefuted);
    }

    /** The in-memory twin of {@link #displayLabel}; the list orders by that expression and serves this value. */
    private static String servedName(CryptoAssetListRow row) {
        return servedName(row.name(), row.oid(), row.identityGuard());
    }

    private static String servedName(String name, String oid, CryptoAssetIdentityGuard guard) {
        if (name != null) {
            return name;
        }
        return guard == CryptoAssetIdentityGuard.REFUTED_OID ? null : oid;
    }

    /**
     * A never-evaluated asset is served as UNKNOWN, the ratified "the rules cannot classify this asset" verdict,
     * because the contract marks the field required.
     */
    private static PqcVerdict servedVerdict(PqcVerdict stored) {
        return stored == null ? PqcVerdict.UNKNOWN : stored;
    }

    /**
     * The contract's sentence -- "sources make contradicting claims ... quarantined pending reconciliation" --
     * describes exactly one guard: REFUTED_CERTIFICATE_DIGEST (contradicting claims, reconciliation queue).
     * BARE_CN_SUBJECT is a permanent DN-scope split with, by the ratified addendum, no reconciliation path at all, and
     * REFUTED_OID is one component contradicting itself; flagging either would advertise an operator queue that can
     * never drain. Widening this needs the flag re-worded in interfaces, not a wider test here.
     */
    private static boolean quarantined(CryptoAssetIdentityGuard guard) {
        return guard == CryptoAssetIdentityGuard.REFUTED_CERTIFICATE_DIGEST;
    }

    private static CryptographicAssetDto toDto(CryptoAssetListRow row) {
        CryptographicAssetDto dto = new CryptographicAssetDto();
        dto.setUuid(row.uuid());
        // The contract marks name REQUIRED and the wire mapper drops nulls, so a nameless producer row serves its
        // recorded OID unless that OID is refuted. A row with no servable label at all serializes without the
        // field; that residual is interfaces' contract friction, raised on the PR.
        dto.setName(servedName(row));
        dto.setType(row.assetType());
        dto.setSourceCbomCount(row.sourceCount());
        dto.setOccurrenceCount(row.occurrenceCount());
        dto.setPqcVerdict(servedVerdict(row.pqcVerdict()));
        dto.setQuarantined(quarantined(row.identityGuard()));
        return dto;
    }

    private static CryptographicAssetDetailDto toDetailDto(CryptoAsset asset, List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        CryptographicAssetDetailDto dto = new CryptographicAssetDetailDto();
        dto.setUuid(asset.getUuid());
        dto.setName(servedName(asset.getName(), asset.getOid(), asset.getIdentityGuard()));
        dto.setType(asset.getAssetType());
        dto.setPqcVerdict(servedVerdict(asset.getPqcVerdict()));
        // GLOBAL badges: computed over every loaded row, before the CBOM visibility filter below, so they keep
        // reconciling with the list (scoped by CRYPTO_ASSET, not CBOM) exactly as the list endpoint serves them --
        // the visibility gate below is on per-document CONTENT, not on whether a document contributed.
        dto.setSourceCbomCount(asset.getSourceCount());
        dto.setOccurrenceCount(sources.stream().mapToLong(CryptoAssetSource::getOccurrenceCount).sum());
        dto.setQuarantined(quarantined(asset.getIdentityGuard()));
        dto.setVerdict(toVerdictDto(asset));
        dto.setNormalizedFields(toNormalizedFieldsDto(asset));
        dto.setElectedPayload(servedElectedPayload(asset, sources, visibleCbomUuids));
        dto.setSources(servedSources(sources, visibleCbomUuids));
        dto.setOids(toOidDtos(asset));
        return dto;
    }

    /**
     * Serial numbers, versions and payloads belong to the CBOM resource -- same rule as
     * {@link #cbomSerialNumbersScopedToCaller} -- so a source is served only for a CBOM the caller may see. Visible
     * rows are then capped at {@link #MAX_SERVED_SOURCES}, oldest-first: {@code sources} already arrives in that order
     * (see {@code CryptoAssetSourceRepository#findWithCbomByAssetUuid}), so filtering before limiting keeps it.
     */
    private static List<CryptographicAssetSourceDto> servedSources(List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        return sources
                .stream()
                .filter(source -> visibleCbomUuids.contains(source.getCbomUuid()))
                .limit(MAX_SERVED_SOURCES)
                .map(CryptographicAssetServiceImpl::toSourceDto)
                .toList();
    }

    /**
     * The elected payload is one document's payload verbatim -- {@code asset.getMergedCryptoProperties()} is not
     * synthesised, it is the electing source's own content -- so unlike the row-level badges (counts) it is gated by
     * that ONE document's visibility, the same rule {@link #servedSources} applies per row. Election itself stays
     * global and deterministic: an invisible electing source suppresses the payload rather than re-electing among
     * whatever the caller can see, which would make the served payload depend on who is asking.
     */
    private static Map<String, Object> servedElectedPayload(CryptoAsset asset, List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        UUID electingSourceUuid = asset.getPropertiesSourceUuid();
        if (electingSourceUuid == null) {
            return null;
        }
        // A pointer naming a row absent from the loaded list (should not happen, but is not this method's invariant
        // to enforce) is treated the same as an invisible one: no visible row, no payload.
        boolean electingDocumentVisible = sources
                .stream()
                .filter(source -> electingSourceUuid.equals(source.getUuid()))
                .findFirst()
                .map(source -> visibleCbomUuids.contains(source.getCbomUuid()))
                .orElse(false);
        return electingDocumentVisible ? asset.getMergedCryptoProperties() : null;
    }

    /**
     * Verdict provenance exists only once a rule set has evaluated the asset; until core#2151 populates verdicts, a
     * fabricated all-default block would present "never evaluated" as a decision, so the block is omitted and the
     * row-level verdict alone says UNKNOWN.
     */
    private static CryptographicAssetVerdictDto toVerdictDto(CryptoAsset asset) {
        if (asset.getPqcEvaluatedAt() == null) {
            return null;
        }
        CryptographicAssetVerdictDto dto = new CryptographicAssetVerdictDto();
        dto.setRuleSetVersion(asset.getPqcRulesetVersion() == null ? 0 : asset.getPqcRulesetVersion());
        dto.setRuleId(asset.getPqcRuleId());
        dto.setReason(asset.getPqcReason());
        dto.setEvaluatedFields(asset.getPqcEvaluatedFields());
        dto.setDecidedAt(asset.getPqcDecidedAt());
        dto.setEvaluatedAt(asset.getPqcEvaluatedAt());
        return dto;
    }

    private static CryptographicAssetNormalizedFieldsDto toNormalizedFieldsDto(CryptoAsset asset) {
        if (asset.getAlgorithmFamily() == null && asset.getPrimitive() == null && asset.getParameterSet() == null
                && asset.getCurve() == null && asset.getMode() == null && asset.getPadding() == null
                && asset.getVariant() == null) {
            return null;
        }
        CryptographicAssetNormalizedFieldsDto dto = new CryptographicAssetNormalizedFieldsDto();
        dto.setAlgorithmFamily(asset.getAlgorithmFamily());
        dto.setPrimitive(asset.getPrimitive());
        dto.setParameterSet(asset.getParameterSet());
        dto.setCurve(asset.getCurve());
        dto.setMode(asset.getMode());
        dto.setPadding(asset.getPadding());
        dto.setVariant(asset.getVariant());
        return dto;
    }

    private static CryptographicAssetSourceDto toSourceDto(CryptoAssetSource source) {
        Cbom cbom = source.getCbom();
        CryptographicAssetSourceDto dto = new CryptographicAssetSourceDto();
        dto.setCbomUuid(source.getCbomUuid());
        dto.setSerialNumber(cbom.getSerialNumber());
        dto.setVersion(cbom.getVersion());
        dto.setOccurrenceCount(source.getOccurrenceCount());
        dto.setSource(cbom.getSource());
        dto.setPayload(source.getOriginalCryptoProperties());
        dto.setEvidence(toEvidenceDtos(source.getEvidence()));
        return dto;
    }

    private static List<CryptographicAssetEvidenceDto> toEvidenceDtos(List<Map<String, Object>> stored) {
        if (stored == null) {
            return null;
        }
        return stored.stream().map(CryptographicAssetServiceImpl::toEvidenceDto).toList();
    }

    /** Stored evidence is the capped producer occurrence array; the keys are CycloneDX occurrence field names. */
    private static CryptographicAssetEvidenceDto toEvidenceDto(Map<String, Object> occurrence) {
        CryptographicAssetEvidenceDto dto = new CryptographicAssetEvidenceDto();
        // location is contract-REQUIRED; the write side (OccurrenceEvidenceCapper#sanitizeLocation) already
        // established "" as the absent-location representation, so the read side must not serve null here either.
        dto.setLocation(Objects.requireNonNullElse(asServedText(occurrence.get("location")), ""));
        dto.setLine(asServedInteger(occurrence.get("line")));
        dto.setOffset(asServedInteger(occurrence.get("offset")));
        dto.setSymbol(asServedText(occurrence.get("symbol")));
        return dto;
    }

    /** A producer occasionally emits a numeric evidence field as a string; the value still names a real position. */
    private static Integer asServedInteger(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.valueOf(text.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /** A locator or symbol served verbatim when textual, or in its decimal form when a producer emitted a number. */
    private static String asServedText(Object value) {
        if (value instanceof String text) {
            return text;
        }
        if (value instanceof Number number) {
            return String.valueOf(number);
        }
        return null;
    }

    private static List<CryptographicAssetOidDto> toOidDtos(CryptoAsset asset) {
        if (asset.getOid() == null) {
            return List.of();
        }
        CryptographicAssetOidDto dto = new CryptographicAssetOidDto();
        dto.setOid(asset.getOid());
        dto.setRefuted(asset.getIdentityGuard() == CryptoAssetIdentityGuard.REFUTED_OID);
        return List.of(dto);
    }
}
