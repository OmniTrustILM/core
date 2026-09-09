package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cbom.CbomDetailDto;
import com.otilm.api.model.core.cbom.CbomDto;
import com.otilm.api.model.core.cbom.CbomUploadRequestDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.ListingSortResolver;
import com.otilm.core.cbom.client.BomSearchPage;
import com.otilm.core.cbom.client.CbomRepositoryClient;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.Cbom_;
import com.otilm.core.dao.entity.ScheduledJobHistory;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.logging.LoggerWrapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.cbom.BomCreateResponseDto;
import com.otilm.core.model.cbom.BomEntryDto;
import com.otilm.core.model.cbom.BomResponseDto;
import com.otilm.core.model.cbom.BomSearchRequestDto;
import com.otilm.core.model.cbom.BomVersionDto;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import com.otilm.core.model.cbom.CbomSyncSkipState;
import com.otilm.core.model.cbom.CryptoStatsDto;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CbomExternalService;
import com.otilm.core.service.CbomInternalService;
import com.otilm.core.service.writer.cbom.CbomSyncSkipWriter;
import com.otilm.core.tasks.CbomSyncTask;
import com.otilm.core.util.CbomUtil;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service(Resource.Codes.CBOM)
@Transactional
public class CbomServiceImpl implements CbomExternalService, CbomInternalService {

    private static final LoggerWrapper logger = new LoggerWrapper(CbomServiceImpl.class, Module.CORE, Resource.CBOM);

    /** Feed entries with this version are the original upload, never a re-synced revision; the sync ignores them. */
    private static final String ORIGINAL_VERSION = "original";

    /**
     * Safety net against a repository that never stops handing out cursors -- ten million entries at the default page
     * size, not a capacity figure any real deployment is expected to approach.
     */
    private static final int MAX_PAGES_PER_RUN = 10_000;

    /**
     * The unique constraint the dedup key is guarded by, declared under this name in both the migration and
     * {@link Cbom}. Only this violation means "another writer got there first"; any other refusal by the database is
     * this entry's problem and is recorded as such rather than counted as a duplicate.
     */
    private static final String DEDUP_CONSTRAINT = "cbom_serial_version_unique";

    private CbomRepository cbomRepository;

    private CbomRepositoryClient cbomRepositoryClient;

    private AttributeEngine attributeEngine;

    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    private TransactionHandler transactionHandler;

    private AttributeColumnProjector attributeColumnProjector;

    private ListingSortResolver listingSortResolver;

    private CbomSyncProperties syncProperties;

    private CbomSyncSkipWriter syncSkipWriter;

    private CbomSyncSkipRepository syncSkipRepository;

    @Autowired
    public void setCbomRepository(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
    }

    @Autowired
    public void setAttributeColumnProjector(AttributeColumnProjector attributeColumnProjector) {
        this.attributeColumnProjector = attributeColumnProjector;
    }

    @Autowired
    public void setListingSortResolver(ListingSortResolver listingSortResolver) {
        this.listingSortResolver = listingSortResolver;
    }

    @Autowired
    public void setCbomRepositoryClient(CbomRepositoryClient cbomRepositoryClient) {
        this.cbomRepositoryClient = cbomRepositoryClient;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setScheduledJobHistoryRepository(ScheduledJobHistoryRepository scheduledJobHistoryRepository) {
        this.scheduledJobHistoryRepository = scheduledJobHistoryRepository;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setSyncProperties(CbomSyncProperties syncProperties) {
        this.syncProperties = syncProperties;
    }

    @Autowired
    public void setSyncSkipWriter(CbomSyncSkipWriter syncSkipWriter) {
        this.syncSkipWriter = syncSkipWriter;
    }

    @Autowired
    public void setSyncSkipRepository(CbomSyncSkipRepository syncSkipRepository) {
        this.syncSkipRepository = syncSkipRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public PaginationResponseDto<CbomDto> listCboms(SecurityFilter filter, SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        final TriFunction<Root<Cbom>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb,
                cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters(), contentFilter);
        final List<CbomDto> cbomDtos = cbomRepository
                .findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p,
                        (root, cb) -> cb.desc(root.get("createdAt")),
                        listingSortResolver.resolve(Resource.CBOM, request.getSort(), contentFilter))
                .stream()
                .map(Cbom::mapToDto)
                .toList();
        attributeColumnProjector
                .project(Resource.CBOM, request.getColumns(), cbomDtos, CbomDto::getUuid, contentFilter);

        final Long maxItems = cbomRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        logger.getLogger().debug("Found {} CBOMs out of {} total", cbomDtos.size(), maxItems);

        final PaginationResponseDto<CbomDto> responseDto = new PaginationResponseDto<>();
        responseDto.setItems(cbomDtos);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.DETAIL)
    public CbomDetailDto getCbomDetail(SecuredUUID uuid) throws CbomRepositoryException, NotFoundException {
        Cbom cbom = getEntity(uuid);

        BomResponseDto response = read(cbom.getSerialNumber(), cbom.getVersion());

        CbomDto cbomDto = cbom.mapToDto();
        CbomDetailDto detailDto = new CbomDetailDto();
        detailDto.setContent(response);
        // cbom dto
        detailDto.setUuid(cbomDto.getUuid());
        detailDto.setCreatedAt(cbomDto.getCreatedAt());
        detailDto.setSerialNumber(cbomDto.getSerialNumber());
        detailDto.setVersion(cbomDto.getVersion());
        detailDto.setSpecVersion(cbomDto.getSpecVersion());
        detailDto.setTimestamp(cbomDto.getTimestamp());
        detailDto.setSource(cbomDto.getSource());
        detailDto.setAlgorithms(cbomDto.getAlgorithms());
        detailDto.setCertificates(cbomDto.getCertificates());
        detailDto.setProtocols(cbomDto.getProtocols());
        detailDto.setCryptoMaterial(cbomDto.getCryptoMaterial());
        detailDto.setTotalAssets(cbomDto.getTotalAssets());
        detailDto.setAssetSyncState(cbomDto.getAssetSyncState());
        detailDto.setAssetSyncedAt(cbomDto.getAssetSyncedAt());

        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public List<CbomDto> getCbomVersions(SecuredUUID uuid) throws NotFoundException {
        List<Cbom> cboms = cbomRepository.findVersionsByUuid(uuid.getValue());

        return cboms.stream().map(Cbom::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.CREATE)
    public CbomDto createCbom(CbomUploadRequestDto request)
            throws AlreadyExistException, CbomRepositoryException, ValidationException {
        Map<String, Object> content = request.getContent();
        if (content == null) {
            throw new ValidationException(ValidationError.create("Request must not be empty"));
        }

        // Extract the required specVersion
        String specVersion = Optional
                .ofNullable(content.get("specVersion"))
                .map(Object::toString)
                .filter(s -> StringUtils.isNotBlank(s))
                .orElseThrow(() -> new ValidationException("specVersion must not be empty"));

        // upload JSON to cbom-repository
        CryptoStatsDto cryptoStats = null;
        String serialNumber = "";
        int version = -1;
        boolean existsInRepository = false;
        try {
            BomCreateResponseDto response = cbomRepositoryClient.create(request);
            logger
                    .logEventDebug(Operation.CREATE, OperationResult.SUCCESS, response,
                            List.of(new ResourceObjectIdentity(response.getSerialNumber(), null)),
                            "CBOM document created in repository with serialNumber %s and version %s"
                                    .formatted(response.getSerialNumber(), response.getVersion()));

            serialNumber = response.getSerialNumber();
            version = response.getVersion();
            cryptoStats = response.getCryptoStats();
        } catch (CbomRepositoryException ex) {
            if (ex.getProblemDetail() != null && ex.getProblemDetail().getStatus() == 409) {
                existsInRepository = true;
                logger
                        .getLogger()
                        .debug("CBOM already exists in cbom-repository (HTTP 409), setting existsInRepository=true");
            } else {
                throw ex;
            }
        }

        if (existsInRepository) {
            serialNumber = CbomUtil.mustGetSerialNumber(request.getContent());
            version = CbomUtil.mustGetVersion(request.getContent());

            List<BomVersionDto> versions = cbomRepositoryClient.versions(serialNumber);

            final String fv = String.valueOf(version);
            final String fsn = serialNumber;
            BomVersionDto matchingVersion = versions
                    .stream()
                    .filter(v -> v.getVersion().equals(fv))
                    .findFirst()
                    .orElseThrow(() -> {
                        logger
                                .getLogger()
                                .warn("CBOM with serialNumber {} and version {} not found in cbom-repository, despite the fact it returned Already Exists error earlier. Try to upload again.",
                                        fsn, fv);
                        ProblemDetail problemDetail = ProblemDetail
                                .forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "CBOM serialNumber and version is reported as existing but was not found in the repository. Please try to upload it again to synchronize state.");
                        return new CbomRepositoryException(problemDetail);
                    });
            cryptoStats = matchingVersion.getCryptoStats();
        }

        // upload stats to database
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(version);
        cbom.setSpecVersion(specVersion);
        cbom.setTimestamp(CbomUtil.getMetadataTimestamp(content).orElse(null));
        cbom.setSource(CbomUtil.getMetadataComponentName(content).orElse(null));
        if (cryptoStats == null) {
            logger
                    .getLogger()
                    .debug("CBOM document retrieved from repository for serialNumber {} and version {} does not contain crypto stats",
                            serialNumber, version);
        }
        CbomHeaderCounts.from(cryptoStats).applyTo(cbom);

        // save into the database only in case it does not exists
        if (cbomRepository.existsBySerialNumberAndVersion(serialNumber, version)) {
            throw new AlreadyExistException(
                    "CBOM with serialNumber %s and version %s already exists".formatted(serialNumber, version));
        }
        try {
            cbomRepository.save(cbom);
        } catch (DataIntegrityViolationException e) {
            throw new AlreadyExistException(
                    "CBOM with serialNumber %s and version %s already exists".formatted(serialNumber, version));
        }
        logger
                .logEvent(Operation.CREATE, OperationResult.SUCCESS, null,
                        List.of(new ResourceObjectIdentity(cbom.getSerialNumber(), cbom.getUuid())),
                        "CBOM record created with serialNumber %s and version %s"
                                .formatted(cbom.getSerialNumber(), cbom.getVersion()));
        return cbom.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.DELETE)
    public void deleteCbom(UUID uuid) throws NotFoundException {
        Cbom cbom = getEntity(SecuredUUID.fromUUID(uuid));
        deleteRow(cbom);
        logger
                .logEvent(Operation.DELETE, OperationResult.SUCCESS, null,
                        List.of(new ResourceObjectIdentity(cbom.getSerialNumber(), cbom.getUuid())),
                        "CBOM record with serialNumber %s and version %s deleted"
                                .formatted(cbom.getSerialNumber(), cbom.getVersion()));
    }

    /**
     * Deletes the row, flushing inside this method so that a refusal from the cryptographic asset inventory -- whose
     * foreign key is RESTRICT -- can be shaped here. Left to the ambient transaction's commit, the violation would
     * surface after the method returns, with only the driver's own text to describe it, and that text quotes the
     * failing row.
     */
    private void deleteRow(Cbom cbom) {
        try {
            cbomRepository.delete(cbom);
            cbomRepository.flush();
        } catch (DataIntegrityViolationException e) {
            throw new ValidationException(ValidationError.create(CryptoAssetConstraintTranslator.describe(e)));
        }
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteCbom(List<UUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();

        if (uuids == null || uuids.isEmpty()) {
            return messages;
        }

        Set<UUID> existingUuids = cbomRepository.findExistingUuids(uuids);
        for (UUID uuid : uuids) {
            if (!existingUuids.contains(uuid)) {
                messages.add(BulkActionMessageDto.failureWithMessage(uuid.toString(), "", "CBOM entry not found"));
                continue;
            }
            try {
                transactionHandler.runInNewTransaction(() -> cbomRepository.deleteById(uuid));
            } catch (Exception ex) {
                // The cryptographic asset inventory's foreign key is RESTRICT, so this is now a reachable failure with
                // a driver message that quotes the failing row. Both the response and the audit entry carry text we
                // shaped instead.
                String safeMessage = ex instanceof DataIntegrityViolationException
                        ? CryptoAssetConstraintTranslator.describe(ex)
                        : "Error deleting CBOM entry";
                messages.add(BulkActionMessageDto.failureWithMessage(uuid.toString(), "", safeMessage));
                logger
                        .logEvent(Operation.DELETE, OperationResult.FAILURE, null,
                                List.of(new ResourceObjectIdentity(null, uuid)), safeMessage);
                continue;
            }
            logger
                    .logEvent(Operation.DELETE, OperationResult.SUCCESS, null,
                            List.of(new ResourceObjectIdentity(null, uuid)), null);
        }

        return messages;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return cbomRepository.findResourceObject(objectUuid, Cbom_.serialNumber);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return cbomRepository.findResourceObject(objectUuid.getValue(), Cbom_.serialNumber);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return cbomRepository.listResourceObjects(filter, Cbom_.serialNumber);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getEntity(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine
                .getResourceSearchableFields(Resource.CBOM, false);

        List<SearchFieldDataDto> fields = List
                .of(SearchHelper.prepareSearch(FilterField.CBOM_SERIAL_NUMBER),
                        SearchHelper.prepareSearch(FilterField.CBOM_VERSION),
                        SearchHelper.prepareSearch(FilterField.CBOM_TIMESTAMP),
                        SearchHelper.prepareSearch(FilterField.CBOM_SOURCE),
                        SearchHelper.prepareSearch(FilterField.CBOM_ALGORITHMS_COUNT),
                        SearchHelper.prepareSearch(FilterField.CBOM_CERTIFICATES_COUNT),
                        SearchHelper.prepareSearch(FilterField.CBOM_PROTOCOLS_COUNT),
                        SearchHelper.prepareSearch(FilterField.CBOM_CRYPTO_MATERIAL_COUNT),
                        SearchHelper.prepareSearch(FilterField.CBOM_TOTAL_ASSETS_COUNT),
                        SearchHelper
                                .prepareSearch(FilterField.CBOM_ASSET_SYNC_STATE,
                                        CbomAssetSyncState.class.getEnumConstants()),
                        SearchHelper.prepareSearch(FilterField.CBOM_ASSETS_SYNCED_AT));

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.getLogger().debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    private Cbom getEntity(SecuredUUID uuid) throws NotFoundException {
        return cbomRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Cbom.class, uuid));
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.CREATE)
    public void syncAuthorized() throws CbomRepositoryException {
        if (!cbomRepositoryClient.isConfigured()) {
            logger.getLogger().debug("CBOM sync: CBOM Repository not configured: skipped;");
            return;
        }
        runSync();
    }

    /**
     * One sync run against the repository's paged search.
     *
     * <p>
     * The run opens with {@code after = start of the last successful run - overlap} and follows the repository's
     * {@code Link rel="next"} header until a page carries none; the absence of the header, not the page size, ends the
     * run. Every entry is deduplicated on {@code (serialNumber, version)} and stored in its own transaction; an entry
     * with {@code cryptoStats: null} is stored with zero counts, left for the asset ingest recount. An entry that could
     * not be stored is recorded in {@code cbom_sync_skip} and retried at the end of the next
     * {@code cbom.sync.skipped-retry-runs} runs, then kept as permanently skipped -- so one failing document can never
     * hold the watermark back, and no entry is lost silently. Any non-2xx answer to a page request fails the run
     * instead: the watermark does not advance and the whole run is repeated. A document read that reaches the sync as
     * HTTP 503 -- the repository declaring itself unavailable, or the client's own refused connection or response
     * timeout -- is charged to that document like any other failure, one hanging document among no other new documents
     * included. Only a run that shows a repository-wide outage -- no read succeeded at all and at least two of the feed
     * pass's documents failed that way -- fails without charging those failures to the retry budget. A retry's failure
     * never counts towards that verdict: the page requests of the same run just succeeded, so the repository is up, and
     * a retry that is exempt from being charged would never spend its budget.
     *
     * <p>
     * Runs without an ambient transaction, and so does the scheduler task calling it: the run pages an external service
     * and reads one document per entry, which must not happen inside the platform's 120 s default transaction. The
     * writes it needs are the entry transactions ({@code REQUIRES_NEW}) and the {@code CbomSyncSkipWriter} methods
     * ({@code REQUIRED}, so each commits on its own).
     */
    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public String sync() throws CbomRepositoryException {
        return runSync();
    }

    /**
     * The run itself, held apart from the two public entry points so that neither reaches it through {@code this}:
     * Spring applies the transaction advice of {@code @Transactional} only to a call arriving from outside the bean, so
     * a self-invocation would run the boundary of whichever caller it came from.
     */
    private String runSync() throws CbomRepositoryException {
        final SyncRun run = new SyncRun(OffsetDateTime.now(), syncProperties.maxAttempts());
        final Map<SyncIdentity, CbomSyncSkip> skips = loadSkipRecords();

        readFeed(run, skips);
        retrySkipped(run, skips);
        settleUnavailable(run);

        final String syncResultMessage = run.summary();
        logger.getLogger().info("CBOM Sync: finished. {}", syncResultMessage);
        return syncResultMessage;
    }

    /**
     * The live retry set: the {@code RETRYING} rows, oldest failure first. Written-off rows stay in the table but are
     * not loaded -- their number only ever grows -- so a row this map does not hold is looked up by identity when an
     * entry fails or is stored ({@link #previousSkip}, {@link #resolveSkipIfRecorded}).
     */
    private Map<SyncIdentity, CbomSyncSkip> loadSkipRecords() {
        final Map<SyncIdentity, CbomSyncSkip> skips = new LinkedHashMap<>();
        for (CbomSyncSkip skip : syncSkipRepository
                .findAllByStateOrderByFirstSkippedAtAscUuidAsc(CbomSyncSkipState.RETRYING)) {
            skips.put(new SyncIdentity(skip.getSerialNumber(), skip.getVersion()), skip);
        }
        return skips;
    }

    /** The entry's skip row as it stood at the start of the run, or null if the entry has never failed before. */
    private CbomSyncSkip previousSkip(SyncIdentity identity, Map<SyncIdentity, CbomSyncSkip> skips) {
        final CbomSyncSkip retrying = skips.get(identity);
        if (retrying != null) {
            return retrying;
        }
        return syncSkipRepository
                .findBySerialNumberAndVersion(identity.serialNumber(), identity.version())
                .orElse(null);
    }

    private void readFeed(SyncRun run, Map<SyncIdentity, CbomSyncSkip> skips) throws CbomRepositoryException {
        final BomSearchRequestDto query = new BomSearchRequestDto();
        query.setAfter(getLastSyncTimestamp());
        query.setLimit(syncProperties.pageSize());
        logger.getLogger().debug("CBOM sync: listing entries created after {}", query.getAfter());

        final Set<URI> requestedPages = new HashSet<>();
        BomSearchPage page = cbomRepositoryClient.search(query);
        while (true) {
            run.pages++;
            if (run.pages > MAX_PAGES_PER_RUN) {
                throw new CbomRepositoryException(ProblemDetail
                        .forStatusAndDetail(HttpStatus.BAD_GATEWAY,
                                "CBOM Repository handed out more than " + MAX_PAGES_PER_RUN + " pages in one run"));
            }
            if (page.hasNext() && page.entries().isEmpty()) {
                // The repository fills a page to the limit while candidates remain and sends a Link only when it
                // stopped before the end of the listing, so an empty page can only ever be the last one. An empty
                // page that still claims a next page is a broken feed; following it would spin until the page
                // ceiling above.
                throw new CbomRepositoryException(ProblemDetail
                        .forStatusAndDetail(HttpStatus.BAD_GATEWAY,
                                "CBOM Repository sent an empty page that still claims a next page"));
            }
            run.read += page.entries().size();
            logger.getLogger().debug("CBOM sync: page {} holds {} CBOM entries", run.pages, page.entries().size());
            for (BomEntryDto entry : page.entries()) {
                processFeedEntry(entry, run, skips);
            }
            if (!page.hasNext()) {
                warnIfTheOpeningPageLooksUnpaged(run, page);
                return;
            }
            if (!requestedPages.add(page.nextPage())) {
                throw new CbomRepositoryException(ProblemDetail
                        .forStatusAndDetail(HttpStatus.BAD_GATEWAY,
                                "CBOM Repository sent a page cursor it had already sent in this run"));
            }
            page = cbomRepositoryClient.nextPage(page);
        }
    }

    /**
     * A repository older than 0.3.0 has no {@code Link} header and no cursor: it answers the search with as much of the
     * listing as {@code limit} allows and says nothing about the rest. From here that is indistinguishable from a
     * complete single page -- so a full opening page without a Link is called out, because Core would otherwise report
     * a clean run over what may be only the first {@code page-size} entries of the listing.
     */
    private void warnIfTheOpeningPageLooksUnpaged(SyncRun run, BomSearchPage page) {
        if (run.pages == 1 && page.entries().size() >= syncProperties.pageSize()) {
            logger
                    .getLogger()
                    .warn("CBOM Sync: the opening page holds {} entries (the requested limit) but carries no Link header; a cbom-repository older than 0.3.0 does not page, so this run may have been truncated. Upgrade every repository replica to 0.3.0 or newer",
                            page.entries().size());
        }
    }

    private void processFeedEntry(BomEntryDto entry, SyncRun run, Map<SyncIdentity, CbomSyncSkip> skips) {
        if (ORIGINAL_VERSION.equals(entry.getVersion())) {
            logger
                    .getLogger()
                    .debug("CBOM Sync: ignoring the original upload of serialNumber {}", entry.getSerialNumber());
            run.originals++;
            return;
        }
        final SyncIdentity identity;
        try {
            identity = identityOf(entry);
        } catch (ValidationException e) {
            logger.getLogger().warn("CBOM Sync: {}", e.getMessage());
            run.invalid++;
            return;
        }
        if (!run.attempted.add(identity)) {
            // The feed offered this identity twice in the same run (e.g. a page overlapping a retried cursor); the
            // first occurrence already carries whatever this run will do for it, so treat the repeat as a duplicate
            // rather than attempting it -- and recording a skip -- a second time.
            logger
                    .getLogger()
                    .debug("CBOM Sync: CBOM serialNumber {} and version {} was already offered earlier in this run; skipping the repeat",
                            identity.serialNumber(), identity.version());
            run.duplicates++;
            return;
        }
        if (cbomRepository.existsBySerialNumberAndVersion(identity.serialNumber(), identity.version())) {
            logger
                    .getLogger()
                    .debug("CBOM Sync: CBOM serialNumber {} and version {}: already exists. Skipping the sync",
                            identity.serialNumber(), identity.version());
            run.duplicates++;
            resolveSkipIfRecorded(identity, skips, run);
            return;
        }

        final CbomHeaderCounts counts = CbomHeaderCounts.from(entry.getCryptoStats());
        final StoreOutcome outcome = store(identity, counts, run);
        switch (outcome.kind()) {
            case STORED -> {
                run.stored++;
                if (entry.hasWarnings()) {
                    logger
                            .getLogger()
                            .warn("CBOM Sync: repository flagged CBOM serialNumber {} version {} with {}; header counts {}",
                                    identity.serialNumber(), identity.version(), entry.getWarnings(),
                                    entry.getCryptoStats() == null
                                            ? "are left at zero until the asset ingest recounts them"
                                            : "were taken from the feed as reported");
                }
                resolveSkipIfRecorded(identity, skips, run);
            }
            case DUPLICATE -> {
                run.duplicates++;
                resolveSkipIfRecorded(identity, skips, run);
            }
            case FAILED -> recordFailure(identity, outcome.reason(), counts, run, previousSkip(identity, skips));
            case UNAVAILABLE -> {
                run.feedDeferred++;
                run.deferred.add(new DeferredSkip(identity, counts, outcome.reason(), previousSkip(identity, skips)));
            }
            default -> throw new IllegalStateException("Unhandled store outcome " + outcome.kind());
        }
    }

    private void retrySkipped(SyncRun run, Map<SyncIdentity, CbomSyncSkip> skips) {
        for (CbomSyncSkip skip : List.copyOf(skips.values())) {
            retrySkippedEntry(skip, run, skips);
        }
    }

    /**
     * One recorded skip's retry. An entry this run's feed pass already attempted is left alone -- that attempt carries
     * whatever the run does for it.
     */
    private void retrySkippedEntry(CbomSyncSkip skip, SyncRun run, Map<SyncIdentity, CbomSyncSkip> skips) {
        final SyncIdentity identity = new SyncIdentity(skip.getSerialNumber(), skip.getVersion());
        if (run.attempted.contains(identity)) {
            return;
        }
        run.retried++;
        if (cbomRepository.existsBySerialNumberAndVersion(identity.serialNumber(), identity.version())) {
            resolveSkipIfRecorded(identity, skips, run);
            return;
        }
        final StoreOutcome outcome = store(identity, skip.counts(), run);
        switch (outcome.kind()) {
            case FAILED -> recordFailure(identity, outcome.reason(), skip.counts(), run, skip);
            case UNAVAILABLE -> run.deferred.add(new DeferredSkip(identity, skip.counts(), outcome.reason(), skip));
            default -> resolveSkipIfRecorded(identity, skips, run);
        }
    }

    /**
     * Reads the document and stores the header row in its own transaction. Never throws for one entry's failure -- the
     * outcome is the caller's signal. A read Core could not get an answer to at all yields {@code UNAVAILABLE} rather
     * than a skip: whether that was this document or the whole repository is only known once every read of the run is
     * done, so the verdict is left to {@link #settleUnavailable(SyncRun)}.
     */
    private StoreOutcome store(SyncIdentity identity, CbomHeaderCounts counts, SyncRun run) {
        final BomResponseDto document;
        try {
            document = read(identity.serialNumber(), identity.version());
            run.successfulReads++;
        } catch (NotFoundException e) {
            return StoreOutcome.failed("document not found in the repository (HTTP 404)");
        } catch (CbomRepositoryException e) {
            final ProblemDetail problemDetail = e.getProblemDetail();
            if (problemDetail == null) {
                return StoreOutcome.unavailable("repository failed the document read (status unknown)");
            }
            final String reason = "repository failed the document read (HTTP " + problemDetail.getStatus() + ")";
            // A 503 is not a verdict on this document: the repository answers it when it is unavailable as a whole, and
            // the client synthesizes it when it never got an answer -- a refused connection, or the response timeout.
            // Any other status the repository chose, 5xx included, is about this document and is charged to it.
            return problemDetail.getStatus() == HttpStatus.SERVICE_UNAVAILABLE.value()
                    ? StoreOutcome.unavailable(reason)
                    : StoreOutcome.failed(reason);
        } catch (RuntimeException e) {
            logger
                    .getLogger()
                    .warn("CBOM Sync: CBOM serialNumber {} and version {}: reading the document failed",
                            identity.serialNumber(), identity.version(), e);
            return StoreOutcome.failed("reading the document failed unexpectedly (see the Core log)");
        }

        final AtomicBoolean isDuplicate = new AtomicBoolean(false);
        try {
            transactionHandler.runInNewTransaction(() -> {
                try {
                    createCbomEntry(identity, counts, document);
                } catch (AlreadyExistException e) {
                    // Pre-check duplicate: no DB operation occurred, transaction is healthy.
                    // AlreadyExistException is checked so it cannot cross the Runnable boundary;
                    // handle it here and signal the result via isDuplicate.
                    isDuplicate.set(true);
                }
            });
        } catch (DataIntegrityViolationException e) {
            if (CryptoAssetConstraintTranslator
                    .constraintNameOf(e)
                    .filter(DEDUP_CONSTRAINT::equalsIgnoreCase)
                    .isEmpty()) {
                // Some other invariant of the `cbom` row was violated -- a column the feed left null, a check
                // constraint. Counting that as a duplicate would drop the entry silently, so it is recorded for retry.
                logger
                        .getLogger()
                        .warn("CBOM Sync: CBOM serialNumber {} and version {}: the database refused the CBOM row",
                                identity.serialNumber(), identity.version(), e);
                return StoreOutcome.failed("storing the CBOM row failed: the database refused it (see the Core log)");
            }
            // Race condition: the dedup key's unique constraint was hit at DB level. The REQUIRES_NEW transaction
            // is already rolled back; count as duplicate rather than an error.
            logger
                    .getLogger()
                    .debug("CBOM Sync: CBOM serialNumber {} and version {}: already exists (unique constraint). Skipping the sync",
                            identity.serialNumber(), identity.version());
            return StoreOutcome.DUPLICATE;
        } catch (ValidationException e) {
            return StoreOutcome.failed("the stored document was refused: " + e.getMessage());
        } catch (RuntimeException e) {
            logger
                    .getLogger()
                    .warn("CBOM Sync: CBOM serialNumber {} and version {}: storing the CBOM row failed",
                            identity.serialNumber(), identity.version(), e);
            return StoreOutcome.failed("storing the CBOM row failed unexpectedly (see the Core log)");
        }
        return isDuplicate.get() ? StoreOutcome.DUPLICATE : StoreOutcome.STORED;
    }

    /**
     * Decides what the reads Core never got an answer to (see {@link #store}) were: this document's failure, or the
     * repository's. Nothing about one such read tells the two apart -- the client answers a refused connection and a
     * response that timed out with the same 503 -- but the run as a whole does. When it looks like an outage
     * ({@link #looksLikeOutage(SyncRun)}) the repository is what failed: the run fails without charging anyone's retry
     * budget, and because the task maps a 503 to a skipped run, the watermark holds and the same entries are offered
     * again. Otherwise each deferred document, a retried one included, is charged for its own failure, exactly as any
     * other failed entry is.
     */
    private void settleUnavailable(SyncRun run) throws CbomRepositoryException {
        if (run.deferred.isEmpty()) {
            return;
        }
        if (looksLikeOutage(run)) {
            throw new CbomRepositoryException(ProblemDetail
                    .forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                            "CBOM Repository failed every document read of this run (" + run.deferred.size()
                                    + " documents); no server-side read failure was charged to the retry budget"
                                    + " and the run is not counted as successful"));
        }
        for (DeferredSkip deferred : run.deferred) {
            recordFailure(deferred.identity(), deferred.reason(), deferred.counts(), run, deferred.previous());
        }
    }

    /**
     * A run shows an outage only when nothing proves the repository serves documents at all: no read succeeded and at
     * least two documents of the feed pass failed server-side. One new document failing on its own is not that
     * evidence, so it is charged like any other failure -- one hanging document must never hold the watermark.
     *
     * <p>
     * The retry phase's failures do not count towards the verdict, however many there are. The page requests of this
     * very run succeeded, so the repository is serving; and a retry the verdict exempted from being charged would keep
     * being exempted in every quiet run to come -- the run skipped every hour, the watermark never recorded again, the
     * budget never spent -- which is the unbounded retry the table exists to prevent. The price is one attempt charged
     * to a retry when an outage begins between the page requests and the retries of the same run.
     */
    private static boolean looksLikeOutage(SyncRun run) {
        return run.successfulReads == 0 && run.feedDeferred >= 2;
    }

    /**
     * Records one entry's failure and charges it to exactly one counter of the report: recorded for retry, written off
     * on this run, or failed again after having been written off earlier -- so an entry is never reported as both
     * queued for retry and given up on.
     */
    private void recordFailure(SyncIdentity identity, String reason, CbomHeaderCounts counts, SyncRun run,
            CbomSyncSkip previous) {
        switch (recordSkip(identity, reason, counts, run, previous)) {
            case RETRYING -> run.recordedForRetry++;
            case WRITTEN_OFF -> run.permanentlySkipped++;
            case ALREADY_WRITTEN_OFF -> run.alreadyPermanent++;
        }
    }

    /**
     * Records one more failed attempt and reports it. A row already permanently skipped before this attempt was
     * reported when that happened, so a further failure of a written-off entry logs at INFO only.
     *
     * @param previous the row's state at the start of this run, or null if this is its first failure ever
     */
    private SkipOutcome recordSkip(SyncIdentity identity, String reason, CbomHeaderCounts counts, SyncRun run,
            CbomSyncSkip previous) {
        final CbomSyncSkip attempted = syncSkipWriter
                .recordAttempt(identity.serialNumber(), identity.version(), reason, counts, run.startedAt,
                        run.maxAttempts);
        if (attempted.getState() != CbomSyncSkipState.PERMANENTLY_SKIPPED) {
            logger
                    .getLogger()
                    .warn("CBOM Sync: CBOM serialNumber {} version {} could not be stored (attempt {} of {}): {}. It is retried on the next run",
                            identity.serialNumber(), identity.version(), attempted.getAttempts(), run.maxAttempts,
                            reason);
            return SkipOutcome.RETRYING;
        }
        if (previous != null && previous.getState() == CbomSyncSkipState.PERMANENTLY_SKIPPED) {
            logger
                    .getLogger()
                    .info("CBOM Sync: CBOM serialNumber {} version {} already permanently skipped; failed again: {}",
                            identity.serialNumber(), identity.version(), reason);
            return SkipOutcome.ALREADY_WRITTEN_OFF;
        }
        logger
                .getLogger()
                .warn("CBOM Sync: CBOM serialNumber {} version {} is permanently skipped after {} attempts: {}",
                        identity.serialNumber(), identity.version(), attempted.getAttempts(), reason);
        return SkipOutcome.WRITTEN_OFF;
    }

    /**
     * Deletes the entry's skip row, if it has one, now that the document is stored. The live retry set answers for
     * {@code RETRYING} rows; a written-off row is looked up, so it too is resolved when its document finally arrives.
     */
    private void resolveSkipIfRecorded(SyncIdentity identity, Map<SyncIdentity, CbomSyncSkip> skips, SyncRun run) {
        if (skips.remove(identity) == null && syncSkipRepository
                .findBySerialNumberAndVersion(identity.serialNumber(), identity.version())
                .isEmpty()) {
            return;
        }
        syncSkipWriter.resolve(identity.serialNumber(), identity.version());
        run.resolved++;
        logger
                .getLogger()
                .info("CBOM Sync: CBOM serialNumber {} version {} is stored; its skip record is resolved",
                        identity.serialNumber(), identity.version());
    }

    private SyncIdentity identityOf(BomEntryDto entry) throws ValidationException {
        if (entry.getSerialNumber() == null) {
            throw new ValidationException(
                    "CBOM entry with missing serial number and version %s".formatted(entry.getVersion()));
        }
        try {
            return new SyncIdentity(entry.getSerialNumber(), Integer.parseInt(entry.getVersion()));
        } catch (NumberFormatException e) {
            throw new ValidationException("CBOM document with serialNumber %s has invalid version %s"
                    .formatted(entry.getSerialNumber(), entry.getVersion()));
        }
    }

    private long getLastSyncTimestamp() {
        Optional<ScheduledJobHistory> lastSync = scheduledJobHistoryRepository
                .findFirstByScheduledJobJobNameAndSchedulerExecutionStatusOrderByJobExecutionDesc(CbomSyncTask.NAME,
                        SchedulerJobExecutionStatus.SUCCESS);

        if (lastSync.isEmpty()) {
            logger.getLogger().debug("CBOM sync: no previous run found, performing initial sync.");
            return 0L;
        }

        ScheduledJobHistory lastSyncJob = lastSync.get();
        Date jobExecution = lastSyncJob.getJobExecution();
        if (jobExecution == null) {
            logger.getLogger().debug("CBOM sync: last sync job has no execution start time, performing initial sync.");
            return 0L;
        }
        return watermarkSeconds(jobExecution, syncProperties.overlap());
    }

    /**
     * The {@code after} bound of a run, in whole seconds: where the last successful run started, less the overlap that
     * covers clock skew and in-flight uploads, and never before the epoch. Package-private and static so the one piece
     * of arithmetic the whole watermark rests on can be pinned without booting a context.
     */
    static long watermarkSeconds(Date lastSuccessfulRunStart, Duration overlap) {
        return Math.max(0L, Math.floorDiv(lastSuccessfulRunStart.getTime(), 1000L) - overlap.toSeconds());
    }

    private void createCbomEntry(SyncIdentity identity, CbomHeaderCounts counts, BomResponseDto response)
            throws AlreadyExistException {
        if (cbomRepository.existsBySerialNumberAndVersion(identity.serialNumber(), identity.version())) {
            throw new AlreadyExistException("CBOM with serialNumber %s and version %s already exists"
                    .formatted(identity.serialNumber(), identity.version()));
        }

        Cbom cbom = new Cbom();
        cbom.setSerialNumber(identity.serialNumber());
        cbom.setVersion(identity.version());
        Optional<String> specVersion = CbomUtil.getString(response, "specVersion");
        if (specVersion.isEmpty()) {
            throw new ValidationException("CBOM Repository returned empty specVersion");
        } else {
            cbom.setSpecVersion(specVersion.get());
        }
        cbom.setTimestamp(CbomUtil.getMetadataTimestamp(response).orElse(null));
        cbom.setSource(CbomUtil.getMetadataComponentName(response).orElse(null));
        counts.applyTo(cbom);
        // Let DataIntegrityViolationException propagate unchecked so the REQUIRES_NEW
        // transaction is not left rollback-only when caught inside the Runnable boundary.
        // The sync loop catches it and counts it as a duplicate when the violated constraint is the
        // (serialNumber, version) uniqueness; any other constraint is recorded for retry.
        cbomRepository.save(cbom);
    }

    public boolean isCbomRepositoryClientConfigured() {
        return cbomRepositoryClient.isConfigured();
    }

    private BomResponseDto read(String serialNumber, int version) throws CbomRepositoryException, NotFoundException {
        BomResponseDto response;
        try {
            response = cbomRepositoryClient.read(serialNumber, version);
            logger
                    .getLogger()
                    .debug("CBOM document retrieved from repository for serialNumber {} and version {}: {}",
                            serialNumber, version, response);
        } catch (CbomRepositoryException ex) {
            if (ex.getProblemDetail() != null && ex.getProblemDetail().getStatus() == 404) {
                throw new NotFoundException("CBOM Repository entry", serialNumber);
            } else {
                throw ex;
            }
        }
        return response;
    }

    /** The pair the repository serves documents by and Core deduplicates on. */
    private record SyncIdentity(String serialNumber, int version) {
    }

    /**
     * What happened to one entry; {@code reason} is operator-safe text, set for {@code FAILED} and {@code UNAVAILABLE}.
     */
    private record StoreOutcome(Kind kind, String reason) {

        enum Kind {
            STORED,
            DUPLICATE,
            FAILED,
            /** The document read got no answer; whose failure that was is decided for the run as a whole. */
            UNAVAILABLE
        }

        static final StoreOutcome STORED = new StoreOutcome(Kind.STORED, null);
        static final StoreOutcome DUPLICATE = new StoreOutcome(Kind.DUPLICATE, null);

        static StoreOutcome failed(String reason) {
            return new StoreOutcome(Kind.FAILED, reason);
        }

        static StoreOutcome unavailable(String reason) {
            return new StoreOutcome(Kind.UNAVAILABLE, reason);
        }
    }

    /** What recording a failed attempt did to the entry's skip row. */
    private enum SkipOutcome {
        RETRYING,
        WRITTEN_OFF,
        ALREADY_WRITTEN_OFF
    }

    /**
     * One entry whose document read got no answer, held until the end of the run.
     *
     * @param previous the skip row's state at the start of the run, or null if the entry has never failed before
     */
    private record DeferredSkip(SyncIdentity identity, CbomHeaderCounts counts, String reason, CbomSyncSkip previous) {
    }

    /** Counters of one run and the identities it has already tried, so the retry phase does not try them twice. */
    private static final class SyncRun {
        final OffsetDateTime startedAt;
        final int maxAttempts;
        final Set<SyncIdentity> attempted = new HashSet<>();
        /** Entries whose document read got no answer, awaiting the run's verdict. */
        final List<DeferredSkip> deferred = new ArrayList<>();
        int pages;
        int read;
        /** Of {@link #deferred}, the entries the feed pass offered; only these weigh in the outage verdict. */
        int feedDeferred;
        int stored;
        int duplicates;
        int originals;
        int invalid;
        int recordedForRetry;
        int retried;
        int resolved;
        int permanentlySkipped;
        int alreadyPermanent;
        int successfulReads;

        SyncRun(OffsetDateTime startedAt, int maxAttempts) {
            this.startedAt = startedAt;
            this.maxAttempts = maxAttempts;
        }

        String summary() {
            return ("Read %d entries in %d pages: stored %d new entries, skipped duplicates %d, ignored %d original documents, "
                    + "%d invalid entries; %d entries could not be stored and were recorded for retry; "
                    + "retried %d previously skipped entries, %d skip records resolved; %d entries are now permanently skipped; "
                    + "%d offers of permanently skipped entries failed again")
                    .formatted(read, pages, stored, duplicates, originals, invalid, recordedForRetry, retried, resolved,
                            permanentlySkipped, alreadyPermanent);
        }
    }
}
