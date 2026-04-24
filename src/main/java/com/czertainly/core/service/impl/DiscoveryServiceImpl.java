package com.czertainly.core.service.impl;

import com.czertainly.api.interfaces.client.v1.DiscoverySyncApiClient;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.DiscoveryResponseDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.czertainly.api.model.client.discovery.DiscoveryDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.AttributeContent;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.handlers.CertificateDiscoveredEventHandler;
import com.czertainly.core.events.handlers.DiscoveryFinishedEventHandler;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.discovery.DiscoveryContext;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.service.handler.CertificateHandler;
import com.czertainly.core.tasks.ScheduledJobInfo;
import com.czertainly.core.util.*;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;

@Service(Resource.Codes.DISCOVERY)
@Transactional
public class DiscoveryServiceImpl implements DiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);

    private static final Semaphore downloadCertSemaphore = new Semaphore(10);

    private final DiscoveryProperties discoveryProperties;

    private EventProducer eventProducer;
    private NotificationProducer notificationProducer;
    private PlatformTransactionManager transactionManager;

    private AttributeEngine attributeEngine;
    private CertificateHandler certificateHandler;

    private TriggerService triggerService;
    private DiscoveryRepository discoveryRepository;
    private CertificateRepository certificateRepository;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorService connectorService;
    private CredentialService credentialService;
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    private CertificateContentRepository certificateContentRepository;

    private ResourceService resourceService;
    private ConnectorRepository connectorRepository;

    public DiscoveryServiceImpl(DiscoveryProperties discoveryProperties) {
        this.discoveryProperties = discoveryProperties;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setTriggerService(TriggerService triggerService) {
        this.triggerService = triggerService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setDiscoveryCertificateHandler(CertificateHandler certificateHandler) {
        this.certificateHandler = certificateHandler;
    }

    @Autowired
    public void setDiscoveryRepository(DiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Autowired
    public void setCertificateContentRepository(CertificateContentRepository certificateContentRepository) {
        this.certificateContentRepository = certificateContentRepository;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public DiscoveryResponseDto listDiscoveries(final SecurityFilter filter, final SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<DiscoveryHistory>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<DiscoveryHistoryDto> listedDiscoveriesDTOs = discoveryRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(DiscoveryHistory::mapToListDto).toList();
        final Long maxItems = discoveryRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final DiscoveryResponseDto responseDto = new DiscoveryResponseDto();
        responseDto.setDiscoveries(listedDiscoveriesDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryHistoryDetailDto getDiscovery(SecuredUUID uuid) throws NotFoundException {
        DiscoveryHistory discoveryHistory = getDiscoveryEntity(uuid);
        DiscoveryHistoryDetailDto dto = discoveryHistory.mapToDto();
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discoveryHistory.getUuid()).build()));
        dto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discoveryHistory.getUuid()).connector(discoveryHistory.getConnectorUuid()).build()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.DISCOVERY, uuid.getValue()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryCertificateResponseDto getDiscoveryCertificates(SecuredUUID uuid,
                                                                    Boolean newlyDiscovered,
                                                                    int itemsPerPage,
                                                                    int pageNumber) throws NotFoundException {
        DiscoveryHistory discoveryHistory = getDiscoveryEntity(uuid);
        // Page number for the user always starts from 1. But for JPA, page number starts from 0
        Pageable p = PageRequest.of(pageNumber > 1 ? pageNumber - 1 : 0, itemsPerPage);
        List<DiscoveryCertificate> certificates;
        Long maxItems;
        if (newlyDiscovered == null) {
            certificates = discoveryCertificateRepository.findByDiscovery(discoveryHistory, p);
            maxItems = discoveryCertificateRepository.countByDiscovery(discoveryHistory);
        } else {
            certificates = discoveryCertificateRepository.findByDiscoveryUuidAndNewlyDiscovered(discoveryHistory.getUuid(), newlyDiscovered, p);
            maxItems = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discoveryHistory, newlyDiscovered);
        }

        final DiscoveryCertificateResponseDto responseDto = new DiscoveryCertificateResponseDto();
        responseDto.setCertificates(certificates.stream().map(DiscoveryCertificate::mapToDto).toList());
        responseDto.setItemsPerPage(itemsPerPage);
        responseDto.setPageNumber(pageNumber);
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / itemsPerPage));
        return responseDto;
    }

    public DiscoveryHistory getDiscoveryEntity(SecuredUUID uuid) throws NotFoundException {
        return discoveryRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(DiscoveryHistory.class, uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    public void deleteDiscovery(SecuredUUID uuid) throws NotFoundException {
        DiscoveryHistory discovery = discoveryRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(DiscoveryHistory.class, uuid));
        Long certsDeleted = discoveryCertificateRepository.deleteByDiscovery(discovery);
        logger.debug("Deleted {} discovery certificates", certsDeleted);

        Integer certContentsDeleted = certificateContentRepository.deleteUnusedCertificateContents();
        logger.debug("Deleted {} unused certificate contents", certContentsDeleted);

        attributeEngine.deleteObjectAttributeContent(Resource.DISCOVERY, discovery.getUuid());
        discoveryRepository.delete(discovery);
        triggerService.deleteTriggerAssociations(Resource.DISCOVERY, discovery.getUuid());

        try {
            String referenceUuid = discovery.getDiscoveryConnectorReference();
            if (referenceUuid != null && !referenceUuid.isEmpty()) {
                Connector connector = connectorRepository.findByUuid(discovery.getConnectorUuid())
                        .orElseThrow(() -> new NotFoundException(Connector.class, discovery.getConnectorUuid()));
                ConnectorApiClientDto connectorDto = connector.mapToApiClientDtoV1();
                connectorApiFactory.getDiscoveryApiClient(connectorDto).removeDiscovery(connectorDto, referenceUuid);
            }
        } catch (ConnectorException e) {
            logger.warn("Failed to delete discovery in the connector. But core history is deleted");
            logger.warn(e.getMessage());
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    @Async
    public void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException {
        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        for (SecuredUUID uuid : discoveryUuids) {
            deleteDiscovery(uuid);
        }
        notificationProducer.produceInternalNotificationMessage(Resource.DISCOVERY, null, NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid), "Discovery histories have been deleted.", null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public Long statisticsDiscoveryCount(SecurityFilter filter) {
        return discoveryRepository.countUsingSecurityFilter(filter, null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public DiscoveryHistoryDetailDto createDiscovery(final DiscoveryDto request, final boolean saveEntity) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        if (discoveryRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(DiscoveryHistory.class, request.getName());
        }
        if (request.getConnectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }
        Connector connector = connectorRepository.findByUuid(UUID.fromString(request.getConnectorUuid()))
                .orElseThrow(() -> new NotFoundException(Connector.class, request.getConnectorUuid()));

        attributeEngine.validateCustomAttributesContent(Resource.DISCOVERY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connector.getUuid()), FunctionGroupCode.DISCOVERY_PROVIDER, request.getAttributes(), request.getKind());

        DiscoveryHistory discovery = new DiscoveryHistory();
        discovery.setName(request.getName());
        discovery.setConnectorName(connector.getName());
        discovery.setStartTime(new Date());
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setKind(request.getKind());

        if (saveEntity) {
            discovery = discoveryRepository.save(discovery);
            attributeEngine.updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(), request.getCustomAttributes());
            attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discovery.getUuid()).connector(connector.getUuid()).build(), request.getAttributes());
            if (request.getTriggers() != null) {
                triggerService.createTriggerAssociations(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY, discovery.getUuid(), request.getTriggers(), false);
                discovery = discoveryRepository.findWithTriggersByUuid(discovery.getUuid());
            }
            return discovery.mapToDto();
        }

        return null;
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public void runDiscoveryAsync(UUID discoveryUuid) {
        runDiscovery(discoveryUuid, null);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public DiscoveryHistoryDetailDto runDiscovery(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        // reload discovery modal with all association since it could be in separate transaction/session due to async
        DiscoveryContext context = loadDiscoveryContext(discoveryUuid);
        DiscoveryHistory discovery = context.getDiscoveryHistory();
        if (context.getDiscoveryStatus() == DiscoveryStatus.FAILED) {
            return finalizeDiscoveryInTx(context, false, null);
        }

        // discover certificates by provider
        DiscoveryProviderDto providerResponse;
        try {
            providerResponse = discoverCertificatesByProvider(context);
            if (context.getConnectorCertificatesDiscovered() == 0) {
                context.setDiscoveryStatus(DiscoveryStatus.COMPLETED);
                return finalizeDiscoveryInTx(context, true, "No certificates discovered at provider");
            }
            updateDiscoveryStateInTx(context, true);
        } catch (DiscoveryException e) {
            logger.error(e.getMessage());
            return finalizeDiscoveryInTx(context, true, null);
        } catch (Exception e) {
            logger.error("Error in discovery '{}' at provider: {}", discovery.getName(), e.getMessage());
            context.setDiscoveryFailed("Error in provider during discovery: " + e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return finalizeDiscoveryInTx(context, true, null);
        }

        // download and create discovered certificates
        List<DiscoveryProviderCertificateDataDto> duplicateCertificates = new ArrayList<>();
        try {
            downloadDiscoveredCertificates(context, providerResponse, duplicateCertificates);
            context.setDiscoveryStatus(DiscoveryStatus.IN_PROGRESS);
            context.setMessage("Discovered certificates downloaded from provider");
        } catch (DiscoveryException e) {
            logger.error(e.getMessage());
        }

        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        // process duplicates
        for (DiscoveryProviderCertificateDataDto certificate : duplicateCertificates) {
            try {
                X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate.getBase64Content());
                String fingerprint = CertificateUtil.getThumbprint(x509Cert.getEncoded());
                Certificate existingCertificate = certificateRepository.findByFingerprint(fingerprint).orElse(null);

                if (existingCertificate == null) {
                    logger.warn("Could not update metadata for duplicate discovery certificate. Certificate with fingerprint {} not found.", fingerprint);
                } else {
                    attributeEngine.updateMetadataAttributes(certificate.getMeta(), ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, existingCertificate.getUuid()).connector(UUID.fromString(context.getConnectorDto().getUuid())).source(Resource.DISCOVERY, discovery.getUuid()).sourceName(discovery.getName()).build());
                }
            } catch (AttributeException e) {
                logger.error("Could not update metadata for duplicate discovery certificate {}.", certificate.getUuid());
            } catch (Exception e) {
                logger.error("Could not parse and process duplicate discovery certificate {}: {}", certificate.getUuid(), e.getMessage());
            }
        }

        context.setCertificatesDiscovered(discoveryCertificateRepository.countByDiscovery(discovery).intValue());
        Long newlyDiscoveredCount = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discovery, true);

        transactionManager.commit(transaction);

        String preProcessingMessage = context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS ? null : context.getMessage();
        if (newlyDiscoveredCount == 0) {
            if (context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS) {
                context.setDiscoveryStatus(DiscoveryStatus.COMPLETED);
            }
            return finalizeDiscoveryInTx(context, false, preProcessingMessage);
        } else {
            context.setDiscoveryStatus(DiscoveryStatus.PROCESSING);
        }

        updateDiscoveryStateInTx(context, false);

        DiscoveryHistoryDetailDto discoveryDto = discovery.mapToDto();
        eventProducer.produceMessage(CertificateDiscoveredEventHandler.constructEventMessage(discovery.getUuid(), context.getLoggedUserUuid(), scheduledJobInfo));
        return discoveryDto;
    }

    private DiscoveryContext loadDiscoveryContext(UUID discoveryUuid) {
        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());

        DefaultTransactionDefinition transactionDef = new DefaultTransactionDefinition();
        transactionDef.setReadOnly(true);
        TransactionStatus transaction = transactionManager.getTransaction(transactionDef);

        // reload discovery modal with all association since it could be in separate transaction/session due to async
        String message = null;
        Connector connector = null;
        List<DataAttribute> dataAttributes = null;
        DiscoveryHistory discovery = discoveryRepository.findWithTriggersByUuid(discoveryUuid);
        try {
            logger.info("Loading discovery context: name={}, uuid={}", discovery.getName(), discovery.getUuid());
            connector = connectorRepository.findByUuid(discovery.getConnectorUuid())
                    .orElseThrow(() -> new NotFoundException(Connector.class, discovery.getConnectorUuid()));
            dataAttributes = attributeEngine.getDefinitionObjectAttributeContent(AttributeType.DATA, connector.getUuid(), null, Resource.DISCOVERY, discovery.getUuid());

            credentialService.loadFullCredentialData(dataAttributes);
            resourceService.loadResourceObjectContentData(dataAttributes);

        } catch (Exception e) {
            message = e.getMessage();
        }

        ConnectorDto connectorDto = connector != null ? connector.mapToDto() : null;
        DiscoveryContext discoveryContext = new DiscoveryContext(loggedUserUuid, connectorDto, discovery, dataAttributes);

        if (message != null) {
            discoveryContext.setMessage(message);
            discoveryContext.setDiscoveryStatus(DiscoveryStatus.FAILED);
            discoveryContext.setConnectorDiscoveryStatus(DiscoveryStatus.FAILED);
        }

        transactionManager.commit(transaction);

        return discoveryContext;
    }

    private DiscoveryProviderDto discoverCertificatesByProvider(final DiscoveryContext context) throws InterruptedException, DiscoveryException {
        DiscoveryHistory discovery = context.getDiscoveryHistory();

        DiscoveryRequestDto dtoRequest = new DiscoveryRequestDto();
        dtoRequest.setName(discovery.getName());
        dtoRequest.setKind(discovery.getKind());
        dtoRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(context.getDataAttributes()));

        DiscoverySyncApiClient discoveryApiClient = connectorApiFactory.getDiscoveryApiClient(context.getConnectorDto());

        // start discovery at provider
        DiscoveryProviderDto response;
        try {
            response = discoveryApiClient.discoverCertificates(context.getConnectorDto(), dtoRequest);
            logger.debug("Discovery start response: name={}, uuid={}, status={}, total={}", discovery.getName(), discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());
            discovery.setDiscoveryConnectorReference(response.getUuid());
        } catch (Exception e) {
            context.setDiscoveryFailed("Failed to run discovery at the provider: " + e.getMessage());
            throw new DiscoveryException(discovery.getName(), context.getMessage());
        }

        if (response.getUuid() == null) {
            context.setDiscoveryFailed("Discovery does not have associated discovery object at provider");
            throw new DiscoveryException(discovery.getName(), context.getMessage());
        }

        DiscoveryDataRequestDto getRequest = new DiscoveryDataRequestDto();
        getRequest.setName(response.getName());
        getRequest.setKind(discovery.getKind());
        getRequest.setPageNumber(1);
        getRequest.setItemsPerPage(discoveryProperties.maxCertificatesPerPage());

        boolean isReachedMaxTime = false;
        while (response.getStatus() == DiscoveryStatus.IN_PROGRESS) {
            logger.debug("Waiting {}ms for discovery to be completed: name={}, uuid={}", discoveryProperties.sleepTimeMs(), discovery.getName(), discovery.getUuid());
            Thread.sleep(discoveryProperties.sleepTimeMs());

            try {
                response = discoveryApiClient.getDiscoveryData(context.getConnectorDto(), getRequest, response.getUuid());
            } catch (ConnectorException e) {
                context.setDiscoveryFailed("Discovery has failed on connector side while waiting for completion");
                throw new DiscoveryException(discovery.getName(), context.getMessage());
            }

            logger.debug("Discovery response: name={}, uuid={}, status={}, total={}", discovery.getName(), discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());

            long secondsElapsed = (new Date().getTime() - discovery.getStartTime().getTime()) / 1000;
            if (!isReachedMaxTime && secondsElapsed > discoveryProperties.maxWaitTimeSeconds()) {
                isReachedMaxTime = true;

                context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                context.setConnectorDiscoveryStatus(response.getStatus());
                context.setConnectorCertificatesDiscovered(response.getTotalCertificatesDiscovered());
                context.setMessage("Discovery exceeded maximum time of %d hours. Please abort the discovery if the provider is stuck in state '%s'."
                        .formatted((int) (discoveryProperties.maxWaitTimeSeconds() / (60 * 60)), DiscoveryStatus.IN_PROGRESS.getLabel()));
                updateDiscoveryStateInTx(context, false);
            } else if (isReachedMaxTime && secondsElapsed > 2 * discoveryProperties.maxWaitTimeSeconds()) {
                context.setDiscoveryStatus(DiscoveryStatus.FAILED);
                context.setConnectorDiscoveryStatus(response.getStatus());
                context.setConnectorCertificatesDiscovered(response.getTotalCertificatesDiscovered());
                context.setMessage("Discovery exceeded maximum time limit and is marked as failed.");
                throw new DiscoveryException(discovery.getName(), context.getMessage());
            }
        }

        if (response.getTotalCertificatesDiscovered() == 0 && response.getStatus() == DiscoveryStatus.FAILED) {
            context.setMetadata(response.getMeta());
            context.setDiscoveryFailed("Discovery has failed on connector side without any certificates found.");
            throw new DiscoveryException(discovery.getName(), context.getMessage());
        }

        context.setDiscoveryStatus(DiscoveryStatus.IN_PROGRESS);
        context.setConnectorDiscoveryStatus(response.getStatus());
        context.setMetadata(response.getMeta());
        context.setMessage("Discovery completed at provider.");
        context.setConnectorCertificatesDiscovered(response.getTotalCertificatesDiscovered());
        return response;
    }

    private void downloadDiscoveredCertificates(final DiscoveryContext context, DiscoveryProviderDto response, List<DiscoveryProviderCertificateDataDto> duplicateCertificates) throws DiscoveryException {
        int currentPage = 1;
        int currentTotal = 0;
        DiscoveryHistory discovery = context.getDiscoveryHistory();

        DiscoveryDataRequestDto getRequest = new DiscoveryDataRequestDto();
        getRequest.setName(response.getName());
        getRequest.setKind(discovery.getKind());
        getRequest.setPageNumber(1);
        getRequest.setItemsPerPage(discoveryProperties.maxCertificatesPerPage());

        List<Future<?>> futures = new ArrayList<>();
        Set<String> uniqueCertificateContents = new HashSet<>();
        DiscoverySyncApiClient discoveryApiClient = connectorApiFactory.getDiscoveryApiClient(context.getConnectorDto());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            while (currentTotal < response.getTotalCertificatesDiscovered()) {
                getRequest.setPageNumber(currentPage);
                getRequest.setItemsPerPage(discoveryProperties.maxCertificatesPerPage());
                try {
                    response = discoveryApiClient.getDiscoveryData(context.getConnectorDto(), getRequest, response.getUuid());
                } catch (ConnectorException e) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context.setMessage("Discovery has failed on connector side while downloading certificates.");
                    throw new DiscoveryException(discovery.getName(), context.getMessage(), e);
                }

                if (response.getCertificateData().isEmpty()) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context.setMessage(String.format("Retrieved only %d certificates but provider discovered %d certificates in total.", currentTotal, response.getTotalCertificatesDiscovered()));
                    throw new DiscoveryException(discovery.getName(), context.getMessage());
                }
                if (response.getCertificateData().size() > discoveryProperties.maxCertificatesPerPage()) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context.setMessage("Too many certificates (%d) in response at page %d. Maximum processable is %d.".formatted(response.getCertificateData().size(), currentPage, discoveryProperties.maxCertificatesPerPage()));
                    throw new DiscoveryException(discovery.getName(), context.getMessage());
                }

                futures.add(downloadDiscoveredCertificatesBatchAsync(discovery, response, context.getConnectorDto(), uniqueCertificateContents, duplicateCertificates, executor, currentPage));

                ++currentPage;
                currentTotal += response.getCertificateData().size();

                if (futures.size() >= discoveryProperties.maxParallelism()) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                }
            }

            // Wait for all tasks to complete
            if (!futures.isEmpty()) {
                handleDiscoveredCertificatesBatch(futures, discovery.getName());
            }
        }
    }

    private Future<?> downloadDiscoveredCertificatesBatchAsync(final DiscoveryHistory discovery, final DiscoveryProviderDto response, final ConnectorDto connector, final Set<String> uniqueCertificateContents, final List<DiscoveryProviderCertificateDataDto> duplicateCertificates, final ExecutorService executor, final int currentPage) {
        // categorize certs and collect metadata definitions
        List<MetadataAttribute> metadataDefinitions = new ArrayList<>();
        Map<String, Set<AttributeContent>> metadataContentsMapping = new HashMap<>();
        List<DiscoveryProviderCertificateDataDto> discoveredCertificates = new ArrayList<>();
        response.getCertificateData().forEach(c -> {
            if (uniqueCertificateContents.contains(c.getBase64Content())) {
                duplicateCertificates.add(c);
            } else {
                discoveredCertificates.add(c);
                uniqueCertificateContents.add(c.getBase64Content());
            }

            for (MetadataAttribute m : c.getMeta()) {
                Set<AttributeContent> metadataContents = metadataContentsMapping.get(m.getUuid());
                if (metadataContents == null) {
                    metadataDefinitions.add(m);
                    metadataContents = new HashSet<>();
                    metadataContentsMapping.put(m.getUuid(), metadataContents);
                }

                metadataContents.addAll(m.getContent());
            }
        });

        // add/update certificate metadata to prevent creating duplicate definitions in parallel processing
        certificateHandler.updateMetadataDefinition(metadataDefinitions, metadataContentsMapping, UUID.fromString(connector.getUuid()), connector.getName());

        // run in separate virtual thread and continue
        return executor.submit(() -> {
            try {
                logger.trace("Waiting to download batch {} of discovered certificates for discovery {}.", currentPage, discovery.getName());
                downloadCertSemaphore.acquire();
                logger.trace("Downloading batch {} of discovered certificates for discovery {}.", currentPage, discovery.getName());

                certificateHandler.createDiscoveredCertificate(String.valueOf(currentPage), discovery, discoveredCertificates);
            } catch (InterruptedException e) {
                logger.error("Downloading batch {} of discovered certificates for discovery {} interrupted.", currentPage, discovery.getName(), e);
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                logger.error("Downloading batch {} of discovered certificates for discovery {} failed.", currentPage, discovery.getName(), e);
            } finally {
                logger.trace("Downloading batch {} of discovered certificates for discovery {} finalized. Released semaphore.", currentPage, discovery.getName());
                downloadCertSemaphore.release();
            }
        });
    }

    private void handleDiscoveredCertificatesBatch(List<Future<?>> futures, String discoveryName) {
        logger.debug("Waiting for {} download tasks for discovery {}", futures.size(), discoveryName);
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                logger.error("An error occurred during downloading discovered certificate of discovery {}: {}", discoveryName, e.getMessage(), e);
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        logger.debug("{} download tasks for discovery {} finished", futures.size(), discoveryName);
        futures.clear();
    }

    private void updateDiscoveryStateInTx(DiscoveryContext discoveryContext, boolean updateMetadata) {
        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        DiscoveryHistory discovery = updateDiscoveryState(discoveryContext, updateMetadata);
        discoveryRepository.save(discovery);
        transactionManager.commit(transaction);
    }

    private DiscoveryHistory updateDiscoveryState(DiscoveryContext discoveryContext, boolean updateMetadata) {
        DiscoveryHistory discovery = discoveryContext.getDiscoveryHistory();

        discovery.setStatus(discoveryContext.getDiscoveryStatus());
        discovery.setConnectorStatus(discoveryContext.getConnectorDiscoveryStatus());
        discovery.setMessage(discoveryContext.getMessage());
        discovery.setTotalCertificatesDiscovered(discoveryContext.getCertificatesDiscovered());
        discovery.setConnectorTotalCertificatesDiscovered(discoveryContext.getConnectorCertificatesDiscovered());
        if (updateMetadata && discoveryContext.getMetadata() != null && !discoveryContext.getMetadata().isEmpty()) {
            try {
                attributeEngine.updateMetadataAttributes(discoveryContext.getMetadata(), ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discovery.getUuid()).connector(discovery.getConnectorUuid()).build());
            } catch (Exception e) {
                logger.warn("Failed to serialize discovery metadata");
            }
        }

        return discovery;
    }

    private DiscoveryHistoryDetailDto finalizeDiscoveryInTx(DiscoveryContext discoveryContext, boolean updateMetadata, String preProcessingMessage) {
        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        DiscoveryHistory discovery = updateDiscoveryState(discoveryContext, updateMetadata);

        discovery.setEndTime(new Date());
        if (discovery.getStatus() == DiscoveryStatus.COMPLETED) {
            discovery.setMessage(preProcessingMessage == null ? "Discovery completed successfully" : "Discovery completed. " + preProcessingMessage);
        }

        discoveryRepository.save(discovery);
        transactionManager.commit(transaction);

        DiscoveryHistoryDetailDto discoveryDto = discovery.mapToDto();
        eventProducer.produceMessage(DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), discoveryContext.getLoggedUserUuid(), null, new DiscoveryResult(discovery.getStatus(), discovery.getMessage())));
        return discoveryDto;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return discoveryRepository.findResourceObject(objectUuid, DiscoveryHistory_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return discoveryRepository.findResourceObject(objectUuid.getValue(), DiscoveryHistory_.name);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        throw new NotSupportedException("Listing of resource objects is not supported for resource discoveries.");
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getDiscoveryEntity(uuid);
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.DISCOVERY, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.CKI_NAME),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_STATUS, Arrays.stream(DiscoveryStatus.values()).map(DiscoveryStatus::getCode).toList()),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_START_TIME),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_END_TIME),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_CONNECTOR_NAME, discoveryRepository.findDistinctConnectorName()),
                SearchHelper.prepareSearch(FilterField.DISCOVERY_KIND)

        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }
}
