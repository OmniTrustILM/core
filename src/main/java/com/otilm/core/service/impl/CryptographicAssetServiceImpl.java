package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomContributedAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetEvidenceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetNormalizedFieldsDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetOidDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetPqcExplanationDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetSourceDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetVerdictDto;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepDto;
import com.otilm.api.model.core.cryptoasset.PqcReferencedAssetDto;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.ListingSortResolver;
import com.otilm.core.cbom.asset.CompositeCurve;
import com.otilm.core.cbom.asset.ServedAssetType;
import com.otilm.core.cbom.pqc.PqcExplanation;
import com.otilm.core.cbom.pqc.PqcRules;
import com.otilm.core.cbom.pqc.PqcVerdictExplainer;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.Cbom_;
import com.otilm.core.dao.entity.UniquelyIdentifiedAndAudited_;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource_;
import com.otilm.core.dao.entity.cbom.CryptoAsset_;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.SortSpecification;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetSourceRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.mapper.workflows.PaginationResponseMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.cbom.CryptoAssetCounts;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.model.cbom.CryptoAssetListRow;
import com.otilm.core.model.cbom.CryptoAssetSourceBomRefsRow;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.ObjectFilterAspect;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.CryptographicAssetExternalService;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.util.CbomAssetSourcePredicates;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import com.otilm.core.util.SortOrderBuilder;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
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

    private PqcVerdictExplainer verdictExplainer;

    @Autowired
    public void setVerdictExplainer(PqcVerdictExplainer verdictExplainer) {
        this.verdictExplainer = verdictExplainer;
    }

    private ListingSortResolver listingSortResolver;

    private AttributeColumnProjector attributeColumnProjector;

    @Autowired
    public void setListingSortResolver(ListingSortResolver listingSortResolver) {
        this.listingSortResolver = listingSortResolver;
    }

    @Autowired
    public void setAttributeColumnProjector(AttributeColumnProjector attributeColumnProjector) {
        this.attributeColumnProjector = attributeColumnProjector;
    }

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
        return findInventoryPage(filter, request, null,
                uuids -> loadRows(uuids).stream().map(CryptographicAssetServiceImpl::toDto).toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.LIST)
    public PaginationResponseDto<CbomContributedAssetDto> listCbomContributedAssets(UUID cbomUuid,
            SearchRequestDto request, SecurityFilter filter) {
        return findInventoryPage(filter, request, (root, cb, query) -> contributedBy(cbomUuid, root, cb, query),
                uuids -> loadContributedRows(cbomUuid, uuids));
    }

    /**
     * The one query pipeline behind every listing in the inventory's shape, so they validate, filter, order, count and
     * project alike and a client pages them the same way. {@code scope} narrows the inventory before the request's
     * filters apply, or is {@code null} for the whole inventory; it must keep the plain count below correct, as an
     * EXISTS does and a join would not. {@code rowsOf} serves the page's uuids as the operation's rows, in page order.
     */
    private <T extends CryptographicAssetDto> PaginationResponseDto<T> findInventoryPage(SecurityFilter filter,
            SearchRequestDto request,
            TriFunction<Root<CryptoAsset>, CriteriaBuilder, CriteriaQuery<?>, Predicate> scope,
            Function<List<UUID>, List<T>> rowsOf) {
        RequestValidatorHelper.revalidateSearchRequestDto(request, Resource.CRYPTO_ASSET);
        validatePaging(request);
        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        TriFunction<Root<CryptoAsset>, CriteriaBuilder, CriteriaQuery<?>, Predicate> where = (root, cb, query) -> {
            Predicate filters = FilterPredicatesBuilder
                    .getFiltersPredicate(cb, query, root, request.getFilters(), contentFilter);
            return scope == null ? filters : cb.and(scope.apply(root, cb, query), filters);
        };
        Pageable page = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        SortSpecification sort = listingSortResolver.resolve(Resource.CRYPTO_ASSET, request.getSort(), contentFilter);
        // A column whose cell serves a derived value is ordered by that value rather than resolved by the repository
        // to its bare column, which would split rows that read the same. The repository still appends the uuid
        // tiebreak (SortOrderBuilder) that keeps page boundaries deterministic.
        SortKey servedKey = servedSortKey(sort);
        List<UUID> pageUuids = servedKey == null
                ? cryptoAssetRepository
                        .findUuidsUsingSecurityFilter(filter, where, page,
                                ordered(CryptographicAssetServiceImpl::displayLabel, SortDirection.ASC), sort)
                : cryptoAssetRepository
                        .findUuidsUsingSecurityFilter(filter, where, page, ordered(servedKey, sort.direction()), null);
        // The plain-count variant: every crypto-asset predicate is either single-column or an EXISTS subquery and
        // the resource declares no groups or owner, so no query shape can duplicate a root row -- and
        // count(DISTINCT) forfeits parallel aggregation, which at millions of rows is seconds per page request.
        long totalItems = cryptoAssetRepository.countRowsUsingSecurityFilter(filter, where);
        List<T> items = rowsOf.apply(pageUuids);
        attributeColumnProjector
                .project(Resource.CRYPTO_ASSET, request.getColumns(), items, CryptographicAssetDto::getUuid,
                        contentFilter);
        return PaginationResponseMapper.toDto(items, request.getPageNumber(), request.getItemsPerPage(), totalItems);
    }

    /**
     * {@link #contributesToAsset} read from the asset side: the source row linking this asset to the given CBOM. An
     * EXISTS rather than a join, for the reason {@code FilterField.CBOM_ASSET_SOURCE_CBOM} gives -- the uuid page query
     * has no DISTINCT, and the plain count depends on nothing duplicating a root row. Keyed on the CBOM's uuid, not its
     * serial number, so the page is one version's contribution.
     */
    private static Predicate contributedBy(UUID cbomUuid, Root<CryptoAsset> root, CriteriaBuilder cb,
            CriteriaQuery<?> query) {
        Subquery<Integer> contributed = query.subquery(Integer.class);
        Root<CryptoAssetSource> source = contributed.from(CryptoAssetSource.class);
        contributed
                .select(cb.literal(1))
                .where(cb.equal(source.get(CryptoAssetSource_.assetUuid), root.get(UniquelyIdentifiedAndAudited_.uuid)),
                        cb.equal(source.get(CryptoAssetSource_.cbomUuid), cbomUuid));
        return cb.exists(contributed);
    }

    /** The page's rows as this CBOM contributed them: each inventory row with this document's refs on it. */
    private List<CbomContributedAssetDto> loadContributedRows(UUID cbomUuid, List<UUID> pageUuids) {
        Map<UUID, List<String>> bomRefsByAsset = bomRefsByAsset(cbomUuid, pageUuids);
        return loadRows(pageUuids)
                .stream()
                .map(row -> toContributedDto(row, bomRefsByAsset.getOrDefault(row.uuid(), List.of())))
                .toList();
    }

    private Map<UUID, List<String>> bomRefsByAsset(UUID cbomUuid, List<UUID> assetUuids) {
        if (assetUuids.isEmpty()) {
            return Map.of();
        }
        return cryptoAssetSourceRepository
                .findBomRefsByCbomUuidAndAssetUuids(cbomUuid, assetUuids)
                .stream()
                .collect(
                        Collectors.toMap(CryptoAssetSourceBomRefsRow::assetUuid, CryptoAssetSourceBomRefsRow::bomRefs));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.DETAIL)
    public CryptographicAssetDetailDto getCryptographicAsset(SecuredUUID uuid) throws NotFoundException {
        CryptoAsset asset = cryptoAssetRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptoAsset.class, uuid));
        List<CryptoAssetSource> sources = cryptoAssetSourceRepository.findWithCbomByAssetUuid(asset.getUuid());
        Set<UUID> visibleCbomUuids = visibleCbomUuids(asset.getUuid());
        CryptographicAssetDetailDto detail = toDetailDto(asset, sources, visibleCbomUuids);
        if (detail.getVerdict() != null) {
            detail.getVerdict().setReferencedAsset(referencedAsset(asset.getPqcReferencedAssetUuid()));
            if (!storedEvidenceVisible(asset, sources, visibleCbomUuids)) {
                detail.getVerdict().setEvaluatedFields(withoutDocumentFields(detail.getVerdict().getEvaluatedFields()));
            }
        }
        return detail;
    }

    /**
     * The asset a verdict was carried over from, as the caller may see it: its name and type only when the row still
     * exists and the caller's own crypto-asset detail access admits it. Resource-level access is already proven by the
     * caller reaching this far, so only the object-level half can differ.
     */
    private PqcReferencedAssetDto referencedAsset(UUID referencedUuid) {
        if (referencedUuid == null) {
            return null;
        }
        PqcReferencedAssetDto dto = new PqcReferencedAssetDto();
        dto.setUuid(referencedUuid);
        Optional<CryptoAsset> target = cryptoAssetRepository.findById(referencedUuid);
        if (target.isPresent() && detailVisible(referencedUuid)) {
            dto.setVisible(true);
            dto.setName(servedName(target.get().getName(), target.get().getOid(), target.get().getIdentityGuard()));
            dto.setType(ServedAssetType.of(target.get().getAssetType()));
        }
        return dto;
    }

    private boolean detailVisible(UUID assetUuid) {
        SecurityFilter filter = SecurityFilter.create();
        objectFilterAspect.populateSecurityFilter(Resource.CRYPTO_ASSET, ResourceAction.DETAIL, null, null, filter);
        return !cryptoAssetRepository
                .findUuidsUsingSecurityFilter(filter, (root, cb, query) -> cb.equal(root.get("uuid"), assetUuid), null,
                        null)
                .isEmpty();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTO_ASSET, action = ResourceAction.DETAIL)
    public CryptographicAssetPqcExplanationDto getCryptographicAssetPqcExplanation(SecuredUUID uuid)
            throws NotFoundException {
        CryptoAsset asset = cryptoAssetRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptoAsset.class, uuid));
        PqcVerdictExplainer.Result result = verdictExplainer
                .explain(asset.getUuid())
                .orElseThrow(() -> new NotFoundException(CryptoAsset.class, uuid));
        List<CryptoAssetSource> sources = cryptoAssetSourceRepository.findWithCbomByAssetUuid(asset.getUuid());
        return toExplanationDto(asset, result,
                electingDocumentVisible(asset, sources, visibleCbomUuids(asset.getUuid())));
    }

    /**
     * Whether the stored verdict's document values may be served: they were copied from the source elected when the
     * verdict was taken, which is the current one only while the row is still at the revision the verdict evaluated --
     * a re-election advances it. A stale verdict may carry a withdrawn or hidden source's values under a visible
     * successor, so it is served without them until the sweep restamps it.
     */
    private static boolean storedEvidenceVisible(CryptoAsset asset, List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        return Objects.equals(asset.getPqcEvaluatedRevision(), asset.getInputRevision())
                && electingDocumentVisible(asset, sources, visibleCbomUuids);
    }

    /**
     * Strips the values the electing document supplied verbatim, for a caller who may not read that document: the same
     * rule that withholds the elected payload, applied to the evidence copied out of it.
     */
    private static Map<String, Object> withoutDocumentFields(Map<String, Object> fields) {
        if (fields == null) {
            return null;
        }
        Map<String, Object> kept = new LinkedHashMap<>(fields);
        kept.keySet().removeAll(PqcRules.DOCUMENT_FIELDS);
        return kept;
    }

    private CryptographicAssetPqcExplanationDto toExplanationDto(CryptoAsset asset, PqcVerdictExplainer.Result result,
            boolean documentVisible) {
        PqcExplanation explanation = result.explanation();
        CryptographicAssetPqcExplanationDto dto = new CryptographicAssetPqcExplanationDto();
        dto.setUuid(asset.getUuid());
        dto.setVerdict(explanation.decision().verdict());
        dto.setRuleId(explanation.decision().ruleId());
        dto.setReason(explanation.decision().reason());
        dto.setInputs(documentVisible ? result.inputs() : withoutDocumentFields(result.inputs()));
        dto.setSteps(explanation.steps().stream().map(step -> toStepDto(step, documentVisible)).toList());
        boolean evaluated = asset.getPqcEvaluatedAt() != null;
        if (evaluated) {
            dto.setStoredVerdict(asset.getPqcVerdict());
            dto.setStoredRuleId(asset.getPqcRuleId());
            dto.setStoredEvaluatedAt(asset.getPqcEvaluatedAt());
        }
        dto
                .setMatchesStored(evaluated && asset.getPqcVerdict() == explanation.decision().verdict()
                        && Objects.equals(asset.getPqcRuleId(), explanation.decision().ruleId())
                        && storedVerdictIsCurrent(asset, result.referenceBasis()));
        dto.setExplainedAt(OffsetDateTime.now());
        return dto;
    }

    /**
     * The sweep's own definition of fresh, so {@code matchesStored} cannot say true for a row the sweep is about to
     * restamp: the stored verdict was taken at the row's current revision, and from the reference verdicts the
     * explanation just read. Agreeing on the verdict alone would hide both.
     */
    private static boolean storedVerdictIsCurrent(CryptoAsset asset, String referenceBasis) {
        return Objects.equals(asset.getPqcEvaluatedRevision(), asset.getInputRevision())
                && Objects.equals(asset.getPqcReferenceBasis(), referenceBasis);
    }

    private PqcExplanationStepDto toStepDto(PqcExplanation.Step step, boolean documentVisible) {
        PqcExplanationStepDto dto = new PqcExplanationStepDto();
        dto.setRuleId(step.ruleId());
        dto.setTitle(step.title());
        dto.setOutcome(step.outcome());
        dto.setVerdict(step.verdict());
        dto.setMessage(step.message());
        dto
                .setEvaluatedFields(
                        documentVisible ? step.evaluatedFields() : withoutDocumentFields(step.evaluatedFields()));
        dto.setReferencedAsset(referencedAsset(step.referencedAssetUuid()));
        return dto;
    }

    /**
     * The CBOM documents whose content the caller may read, scoped by the caller's own {@code cboms:list} object access
     * -- serial numbers and payloads belong to the CBOM resource, the same rule
     * {@link #cbomSerialNumbersScopedToCaller} applies to the source-CBOM value list. Narrowed to the documents that
     * actually contribute to this asset, mirroring {@link CbomAssetSourcePredicates#hasContributedAssets}, so the
     * EXISTS subquery stays cheap.
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
     * {@link CbomAssetSourcePredicates#hasContributedAssets}, narrowed to one asset: the EXISTS subquery a per-detail
     * visibility scope needs.
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
                            .countUsingSecurityFilter(cbomFilter, CbomAssetSourcePredicates::hasContributedAssets));
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

    /** The list rows for a page of uuids, in the page's order; a uuid whose row vanished in between is skipped. */
    private List<CryptoAssetListRow> loadRows(List<UUID> pageUuids) {
        if (pageUuids.isEmpty()) {
            return List.of();
        }
        Map<UUID, CryptoAssetListRow> rowsByUuid = cryptoAssetRepository
                .findListRowsByUuids(pageUuids)
                .stream()
                .collect(Collectors.toMap(CryptoAssetListRow::uuid, Function.identity()));
        return pageUuids.stream().map(rowsByUuid::get).filter(Objects::nonNull).toList();
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

    private interface SortKey extends BiFunction<Root<CryptoAsset>, CriteriaBuilder, Expression<?>> {
    }

    /**
     * The value a cell serves where it differs from its column: the display label for the name, no type for a stored
     * tier CycloneDX has no value for, and UNKNOWN for a never-evaluated verdict, as {@link #servedName},
     * {@link ServedAssetType#of} and {@link #servedVerdict} serve them. {@code null} for any other sort, which the
     * repository resolves to the column itself.
     */
    private static SortKey servedSortKey(SortSpecification sort) {
        if (sort == null || sort.fieldSource() != FilterFieldSource.PROPERTY) {
            return null;
        }
        if (FilterField.CBOM_ASSET_NAME.name().equals(sort.fieldIdentifier())) {
            return CryptographicAssetServiceImpl::displayLabel;
        }
        if (FilterField.CBOM_ASSET_TYPE.name().equals(sort.fieldIdentifier())) {
            return CryptographicAssetServiceImpl::servedAssetType;
        }
        if (FilterField.CBOM_ASSET_PQC_VERDICT.name().equals(sort.fieldIdentifier())) {
            return (root, cb) -> cb.coalesce(root.get(CryptoAsset_.pqcVerdict), PqcVerdict.UNKNOWN);
        }
        return null;
    }

    private static Expression<CryptographicAssetType> servedAssetType(Root<CryptoAsset> root, CriteriaBuilder cb) {
        Path<CryptographicAssetType> stored = root.get(CryptoAsset_.assetType);
        return cb
                .<CryptographicAssetType>selectCase()
                .when(stored.in(ServedAssetType.VALUES), stored)
                .otherwise(cb.nullLiteral(CryptographicAssetType.class));
    }

    /** Rows with nothing to serve stay last in either direction, as they do under every other column sort. */
    private static BiFunction<Root<CryptoAsset>, CriteriaBuilder, Order> ordered(SortKey key, SortDirection direction) {
        return (root, cb) -> SortOrderBuilder.primary(cb, key.apply(root, cb), direction);
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
        return fill(new CryptographicAssetDto(), row);
    }

    private static CbomContributedAssetDto toContributedDto(CryptoAssetListRow row, List<String> bomRefs) {
        CbomContributedAssetDto dto = fill(new CbomContributedAssetDto(), row);
        dto.setBomRefs(bomRefs);
        return dto;
    }

    /** The inventory row's served members, on whichever row shape the operation returns. */
    private static <T extends CryptographicAssetDto> T fill(T dto, CryptoAssetListRow row) {
        dto.setUuid(row.uuid());
        // The contract marks name REQUIRED and the wire mapper drops nulls, so a nameless producer row serves its
        // recorded OID unless that OID is refuted. A row with no servable label at all serializes without the
        // field; that residual is interfaces' contract friction, raised on the PR.
        dto.setName(servedName(row));
        dto.setType(ServedAssetType.of(row.assetType()));
        CryptoAssetCounts counts = new CryptoAssetCounts(Math.toIntExact(row.sourceCount()), row.occurrenceCount());
        dto.setSourceCbomCount(counts.sourceCount());
        dto.setOccurrenceCount(counts.occurrenceCount());
        dto.setPqcVerdict(servedVerdict(row.pqcVerdict()));
        dto.setQuarantined(quarantined(row.identityGuard()));
        return dto;
    }

    private static CryptographicAssetDetailDto toDetailDto(CryptoAsset asset, List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        CryptographicAssetDetailDto dto = new CryptographicAssetDetailDto();
        dto.setUuid(asset.getUuid());
        dto.setName(servedName(asset.getName(), asset.getOid(), asset.getIdentityGuard()));
        dto.setType(ServedAssetType.of(asset.getAssetType()));
        dto.setPqcVerdict(servedVerdict(asset.getPqcVerdict()));
        // GLOBAL badges: computed over every loaded row, before the CBOM visibility filter below, so they keep
        // reconciling with the list (scoped by CRYPTO_ASSET, not CBOM) exactly as the list endpoint serves them --
        // the visibility gate below is on per-document CONTENT, not on whether a document contributed. Both counts
        // come from this one read so a concurrent withdrawal cannot leave them disagreeing.
        List<Integer> occurrenceCountPerSource = sources.stream().map(CryptoAssetSource::getOccurrenceCount).toList();
        CryptoAssetCounts counts = CryptoAssetCounts.ofSourceOccurrenceCounts(occurrenceCountPerSource);
        dto.setSourceCbomCount(counts.sourceCount());
        dto.setOccurrenceCount(counts.occurrenceCount());
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
        return electingDocumentVisible(asset, sources, visibleCbomUuids) ? asset.getMergedCryptoProperties() : null;
    }

    /**
     * Whether the caller may read the document whose payload the merge elected. A pointer naming a row absent from the
     * loaded list (should not happen, but is not this method's invariant to enforce) is treated the same as an
     * invisible one.
     */
    private static boolean electingDocumentVisible(CryptoAsset asset, List<CryptoAssetSource> sources,
            Set<UUID> visibleCbomUuids) {
        UUID electingSourceUuid = asset.getPropertiesSourceUuid();
        return electingSourceUuid != null && sources
                .stream()
                .filter(source -> electingSourceUuid.equals(source.getUuid()))
                .findFirst()
                .map(source -> visibleCbomUuids.contains(source.getCbomUuid()))
                .orElse(false);
    }

    /**
     * Verdict provenance exists only once a rule set has evaluated the asset, and a row without it is reachable by
     * design, not only before the rule set shipped: a row waits between its upsert and its first evaluation (only the
     * sweep evaluates until ingest does), and a row whose first verdict write failed or was refused by the row-version
     * guard stays on the work list -- the {@code pqc_evaluated_revision} arm of the sweep's query offers both again on
     * the next run. A failed <em>evaluation</em> is not one of these: the sweep stamps it {@code UNKNOWN} /
     * {@code EVALUATION-FAILED} with a current {@code pqc_evaluated_at}, so that row serves a block naming the failure
     * and leaves the work list. Until a row is stamped, a fabricated all-default block would present "never evaluated"
     * as a decision, so the block is omitted -- the contract marks it not required (interfaces#938, PR interfaces#940)
     * -- and the row-level verdict alone says UNKNOWN.
     */
    private static CryptographicAssetVerdictDto toVerdictDto(CryptoAsset asset) {
        if (asset.getPqcEvaluatedAt() == null) {
            return null;
        }
        CryptographicAssetVerdictDto dto = new CryptographicAssetVerdictDto();
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
        dto.setCurve(CompositeCurve.join(asset.getCurve()));
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
