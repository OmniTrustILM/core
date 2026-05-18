package com.czertainly.core.service.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.lang3.StringUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.CbomRepositoryException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.cbom.CbomDetailDto;
import com.czertainly.api.model.core.cbom.CbomDto;
import com.czertainly.api.model.core.cbom.CbomUploadRequestDto;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.logging.enums.OperationResult;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.cbom.client.CbomRepositoryClient;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.Cbom;
import com.czertainly.core.dao.entity.Cbom_;
import com.czertainly.core.dao.entity.ScheduledJobHistory;
import com.czertainly.core.dao.repository.CbomRepository;
import com.czertainly.core.dao.repository.ScheduledJobHistoryRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.transaction.TransactionHandler;
import com.czertainly.core.logging.LoggerWrapper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.cbom.BomCreateResponseDto;
import com.czertainly.core.model.cbom.BomEntryDto;
import com.czertainly.core.model.cbom.BomResponseDto;
import com.czertainly.core.model.cbom.BomVersionDto;
import com.czertainly.core.model.cbom.CryptoStatsDto;
import com.czertainly.core.model.cbom.BomSearchRequestDto;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CbomService;
import com.czertainly.core.tasks.CbomSyncTask;
import com.czertainly.core.util.CbomUtil;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

@Service(Resource.Codes.CBOM)
@Transactional
public class CbomServiceImpl implements CbomService {

    private static final LoggerWrapper logger = new LoggerWrapper(CbomServiceImpl.class, Module.CORE, Resource.CBOM);

    private CbomRepository cbomRepository;

    private CbomRepositoryClient cbomRepositoryClient;

    private AttributeEngine attributeEngine;

    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    private TransactionHandler transactionHandler;

    @Autowired
    public void setCbomRepository(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
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

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public PaginationResponseDto<CbomDto> listCboms(SecurityFilter filter, SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<Cbom>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<CbomDto> cbomDtos = cbomRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("createdAt")))
                .stream()
                .map(Cbom::mapToDto).toList();
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

        BomResponseDto response = read(
                cbom.getSerialNumber(),
                cbom.getVersion()
        );

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

        return detailDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.LIST)
    public List<CbomDto> getCbomVersions(SecuredUUID uuid) throws NotFoundException {
        List<Cbom> cboms = cbomRepository.findVersionsByUuid(uuid.getValue());

        return cboms
                .stream()
                .map(Cbom::mapToDto)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.CREATE)
    public CbomDto createCbom(CbomUploadRequestDto request) throws AlreadyExistException, CbomRepositoryException, ValidationException {
        Map<String, Object> content = request.getContent();
        if (content == null) {
            throw new ValidationException(
                    ValidationError.create("Request must not be empty")
            );
        }

        // Extract the required specVersion
        String specVersion = Optional.ofNullable(content.get("specVersion"))
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
            logger.logEventDebug(Operation.CREATE, OperationResult.SUCCESS, response, List.of(new ResourceObjectIdentity(response.getSerialNumber(), null)), "CBOM document created in repository with serialNumber %s and version %s".formatted(response.getSerialNumber(), response.getVersion()));

            serialNumber = response.getSerialNumber();
            version = response.getVersion();
            cryptoStats = response.getCryptoStats();
        } catch (CbomRepositoryException ex) {
            if (ex.getProblemDetail() != null && ex.getProblemDetail().getStatus() == 409) {
                existsInRepository = true;
                logger.getLogger().debug("CBOM already exists in cbom-repository (HTTP 409), setting existsInRepository=true");
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
            BomVersionDto matchingVersion = versions.stream()
            .filter(v -> v.getVersion().equals(fv))
            .findFirst()
            .orElseThrow(() -> {
                logger.getLogger().warn("CBOM with serialNumber {} and version {} not found in cbom-repository, despite the fact it returned Already Exists error earlier. Try to upload again.", fsn, fv);
                ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "CBOM serialNumber and version is reported as existing but was not found in the repository. Please try to upload it again to synchronize state.");
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
        setCryptoStats(cbom, serialNumber, version, cryptoStats);

        // save into the database only in case it does not exists
        if (cbomRepository.existsBySerialNumberAndVersion(serialNumber, version)) {
             throw new AlreadyExistException(
                "CBOM with serialNumber %s and version %s already exists".formatted(serialNumber, version)
            );
        }
        try {
            cbomRepository.save(cbom);
        } catch (DataIntegrityViolationException e) {
            throw new AlreadyExistException(
                "CBOM with serialNumber %s and version %s already exists".formatted(serialNumber, version)
            );
        }
        logger.logEvent(Operation.CREATE, OperationResult.SUCCESS, null, List.of(new ResourceObjectIdentity(cbom.getSerialNumber(), cbom.getUuid())), "CBOM record created with serialNumber %s and version %s".formatted(cbom.getSerialNumber(), cbom.getVersion()));
        return cbom.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.DELETE)
    public void deleteCbom(UUID uuid) throws NotFoundException {
        Cbom cbom = getEntity(SecuredUUID.fromUUID(uuid));
        cbomRepository.delete(cbom);
        logger.logEvent(Operation.DELETE, OperationResult.SUCCESS, null, List.of(new ResourceObjectIdentity(cbom.getSerialNumber(), cbom.getUuid())), "CBOM record with serialNumber %s and version %s deleted".formatted(cbom.getSerialNumber(), cbom.getVersion()));
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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), "", ex, "Error deleting CBOM entry"));
                logger.logEvent(Operation.DELETE, OperationResult.FAILURE, null, List.of(new ResourceObjectIdentity(null, uuid)), ex.getMessage());
                continue;
            }
            logger.logEvent(Operation.DELETE, OperationResult.SUCCESS, null, List.of(new ResourceObjectIdentity(null, uuid)), null);
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
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return cbomRepository.listResourceObjects(filter, Cbom_.serialNumber);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getEntity(uuid);
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CBOM, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.CBOM_SERIAL_NUMBER),
                SearchHelper.prepareSearch(FilterField.CBOM_VERSION),
                SearchHelper.prepareSearch(FilterField.CBOM_TIMESTAMP),
                SearchHelper.prepareSearch(FilterField.CBOM_SOURCE),
                SearchHelper.prepareSearch(FilterField.CBOM_ALGORITHMS_COUNT),
                SearchHelper.prepareSearch(FilterField.CBOM_CERTIFICATES_COUNT),
                SearchHelper.prepareSearch(FilterField.CBOM_PROTOCOLS_COUNT),
                SearchHelper.prepareSearch(FilterField.CBOM_CRYPTO_MATERIAL_COUNT),
                SearchHelper.prepareSearch(FilterField.CBOM_TOTAL_ASSETS_COUNT)
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.getLogger().debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

    private Cbom getEntity(SecuredUUID uuid) throws NotFoundException {
        return cbomRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Cbom.class, uuid));
    }

    private void setCryptoStats(Cbom cbom, String serialNumber, int version, CryptoStatsDto cryptoStats) {
        // Defensive handling of potentially null nested response objects
        int algorithmsCount = 0;
        int certificatesCount = 0;
        int protocolsCount = 0;
        int cryptoMaterialCount = 0;
        int totalAssetsCount = 0;
        if (cryptoStats != null && cryptoStats.getCryptoAssets() != null) {
            if (cryptoStats.getCryptoAssets().getAlgorithms() != null
                    && cryptoStats.getCryptoAssets().getAlgorithms().getTotal() != null) {
                algorithmsCount = cryptoStats.getCryptoAssets().getAlgorithms().getTotal();
            }
            if (cryptoStats.getCryptoAssets().getCertificates() != null
                    && cryptoStats.getCryptoAssets().getCertificates().getTotal() != null) {
                certificatesCount = cryptoStats.getCryptoAssets().getCertificates().getTotal();
            }
            if (cryptoStats.getCryptoAssets().getProtocols() != null
                    && cryptoStats.getCryptoAssets().getProtocols().getTotal() != null) {
                protocolsCount = cryptoStats.getCryptoAssets().getProtocols().getTotal();
            }
            if (cryptoStats.getCryptoAssets().getRelatedCryptoMaterials() != null
                    && cryptoStats.getCryptoAssets().getRelatedCryptoMaterials().getTotal() != null) {
                cryptoMaterialCount = cryptoStats.getCryptoAssets().getRelatedCryptoMaterials().getTotal();
            }
            if (cryptoStats.getCryptoAssets().getTotal() != null) {
                totalAssetsCount = cryptoStats.getCryptoAssets().getTotal();
            }
        } else {
            logger.getLogger().debug("CBOM document retrieved from repository for serialNumber {} and version {} does not contain crypto stats", serialNumber, version);
        }

        cbom.setAlgorithmsCount(algorithmsCount);
        cbom.setCertificatesCount(certificatesCount);
        cbom.setProtocolsCount(protocolsCount);
        cbom.setCryptoMaterialCount(cryptoMaterialCount);
        cbom.setTotalAssetsCount(totalAssetsCount);
    }

    @ExternalAuthorization(resource = Resource.CBOM, action = ResourceAction.CREATE)
    public void syncAuthorized() throws CbomRepositoryException {
        if (!cbomRepositoryClient.isConfigured()) {
            logger.getLogger().debug("CBOM sync: CBOM Repository not configured: skipped;");
            return;
        }
        sync();
    }

    public String sync() throws CbomRepositoryException {
        long timestamp = getLastSyncTimestamp();
        BomSearchRequestDto query = new BomSearchRequestDto();
        query.setAfter(timestamp);
        List<BomEntryDto> cboms = cbomRepositoryClient.search(query);
        logger.getLogger().debug("CBOM sync: {} CBOM entries retrieved from repository for after: {}", cboms.size(), query.getAfter());

        int skipped = 0;
        int duplicates = 0;
        int stored = 0;

        for (BomEntryDto entry : cboms) {
            int version;
            try {
                version = validateSyncedCbomEntry(entry);
            } catch (AlreadyExistException e) {
                logger.getLogger().debug("CBOM Sync: {}", e.getMessage());
                duplicates++;
                continue;
            } catch (ValidationException e) {
                logger.getLogger().debug("CBOM Sync: {}", e.getMessage());
                skipped++;
                continue;
            }

            // specVersion, source and metadata.timestamp arguments missing from BomEntryDto
            // - load them from CBOM itself
            BomResponseDto response;
            try {
                response = read(entry.getSerialNumber(), version);
            } catch (NotFoundException e) {
                logger.getLogger().warn("CBOM Sync: CBOM serialNumber {} and version {}: not exists. Skipping the sync", entry.getSerialNumber(), version);
                skipped++;
                continue;
            } catch (Exception ex) {
                logger.getLogger().warn("CBOM Sync: CBOM serialNumber {} and version {}: error while reading the CBOM document from repository. Skipping the sync. Error: {}", entry.getSerialNumber(), version, ex.getMessage());
                skipped++;
                continue;
            }


            AtomicBoolean isDuplicate = new AtomicBoolean(false);
            try {
                transactionHandler.runInNewTransaction(() -> {
                    try {
                        createCbomEntry(entry, version, response);
                    } catch (AlreadyExistException e) {
                        // Pre-check duplicate: no DB operation occurred, transaction is healthy.
                        // AlreadyExistException is checked so it cannot cross the Runnable boundary;
                        // handle it here and signal the result via isDuplicate.
                        isDuplicate.set(true);
                    }
                });
            } catch (DataIntegrityViolationException e) {
                // Race condition: unique constraint hit at DB level. The REQUIRES_NEW transaction
                // is already rolled back; count as duplicate rather than an error.
                logger.getLogger().debug("CBOM Sync: CBOM serialNumber {} and version {}: already exists (unique constraint). Skipping the sync", entry.getSerialNumber(), version);
                duplicates++;
                continue;
            } catch (Exception e) {
                logger.getLogger().debug("CBOM Sync: CBOM serialNumber {} and version {} syncing error {}.", entry.getSerialNumber(), version, e.getMessage());
                skipped++;
                continue;
            }
            if (isDuplicate.get()) {
                logger.getLogger().debug("CBOM Sync: CBOM serialNumber {} and version {}: already exists. Skipping the sync", entry.getSerialNumber(), version);
                duplicates++;
                continue;
            }
            stored++;
        }

        String syncResultMessage = "Read %d entries, skipped due to an error %d, skipped duplicates %d, stored %d new entries".formatted(
                cboms.size(),
                skipped,
                duplicates,
                stored
        );
        logger.getLogger().info("CBOM Sync: finished. {}", syncResultMessage);

        return syncResultMessage;
    }

    public boolean isCbomRepositoryClientConfigured() {
        return cbomRepositoryClient.isConfigured();
    }

    private BomResponseDto read(String serialNumber, int version) throws CbomRepositoryException, NotFoundException {
        BomResponseDto response;
        try {
            response = cbomRepositoryClient.read(
                    serialNumber,
                    version);
            logger.getLogger().debug("CBOM document retrieved from repository for serialNumber {} and version {}: {}", serialNumber, version, response);
        } catch (CbomRepositoryException ex) {
            if (ex.getProblemDetail() != null && ex.getProblemDetail().getStatus() == 404) {
                throw new NotFoundException("CBOM Repository entry", serialNumber);
            } else {
                throw ex;
            }
        }
        return response;
    }

    private int validateSyncedCbomEntry(BomEntryDto entry) throws ValidationException, AlreadyExistException {
        if (entry.getSerialNumber() == null) {
            throw new ValidationException("CBOM entry with missing serial number and version %s".formatted(entry.getVersion()));
        }

        int version;
        try {
            version = Integer.parseInt(entry.getVersion());
        } catch (NumberFormatException e) {
            throw new ValidationException("CBOM document with serialNumber %s has invalid version %s".formatted(entry.getSerialNumber(), entry.getVersion()));
        }

        boolean cbomVersionExists = cbomRepository.existsBySerialNumberAndVersion(entry.getSerialNumber(), version);
        if (cbomVersionExists) {
            throw new AlreadyExistException("CBOM document with serial number %s and version %s already exists. Skipping the sync".formatted(entry.getSerialNumber(), version));
        }

        return version;
    }

    private long getLastSyncTimestamp() {
        Optional<ScheduledJobHistory> lastSync = scheduledJobHistoryRepository.findFirstByScheduledJobJobNameAndSchedulerExecutionStatusOrderByJobExecutionDesc(CbomSyncTask.NAME, SchedulerJobExecutionStatus.SUCCESS);

        if (lastSync.isEmpty()) {
            logger.getLogger().debug("CBOM sync: no previous run found, performing initial sync.");
            return 0L;
        }

        long timestamp = 0L;
        ScheduledJobHistory lastSyncJob = lastSync.get();
        Date jobExecution = lastSyncJob.getJobExecution();
        if (jobExecution == null) {
            logger.getLogger().debug("CBOM sync: last sync job has no execution start time, performing initial sync.");
        } else {
            long safetyOverlapSeconds = 60L;
            long baseTimestamp = jobExecution.getTime() / 1000;
            timestamp = Math.max(0L, baseTimestamp - safetyOverlapSeconds);
        }
        return timestamp;
    }

    private void createCbomEntry(BomEntryDto entry, int version, BomResponseDto response) throws AlreadyExistException {
        String serialNumber = entry.getSerialNumber();
        if (cbomRepository.existsBySerialNumberAndVersion(serialNumber, version)) {
            throw new AlreadyExistException(
                "CBOM with serialNumber %s and version %s already exists".formatted(serialNumber, version)
            );
        }

        Cbom cbom = new Cbom();
        cbom.setSerialNumber(entry.getSerialNumber());
        cbom.setVersion(version);
        Optional<String> specVersion = CbomUtil.getString(response, "specVersion");
        if (specVersion.isEmpty()) {
            throw new ValidationException("CBOM Repository returned empty specVersion");
        } else {
            cbom.setSpecVersion(specVersion.get());
        }
        cbom.setTimestamp(CbomUtil.getMetadataTimestamp(response).orElse(null));
        cbom.setSource(CbomUtil.getMetadataComponentName(response).orElse(null));
        cbom.setAlgorithmsCount(entry.getCryptoStats().getCryptoAssets().getAlgorithms().getTotal());
        cbom.setCertificatesCount(entry.getCryptoStats().getCryptoAssets().getCertificates().getTotal());
        cbom.setProtocolsCount(entry.getCryptoStats().getCryptoAssets().getProtocols().getTotal());
        cbom.setCryptoMaterialCount(entry.getCryptoStats().getCryptoAssets().getRelatedCryptoMaterials().getTotal());
        cbom.setTotalAssetsCount(entry.getCryptoStats().getCryptoAssets().getTotal());
        // Let DataIntegrityViolationException propagate unchecked so the REQUIRES_NEW
        // transaction is not left rollback-only when caught inside the Runnable boundary.
        // The sync loop catches it specifically and counts it as a duplicate.
        cbomRepository.save(cbom);
    }
}
