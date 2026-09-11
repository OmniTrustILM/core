package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.DiscoveryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v1.DiscoverySyncApiClient;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.model.discovery.DiscoveryContext;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.DiscoveryProperties;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

/**
 * The v1 (legacy) discovery flow, kept behavior-frozen: start the run at the provider, wait for completion, download
 * the certificate pages, and hand the staged results to processing.
 *
 * <p>
 * The v1 discovery interface has no run lifecycle, so {@link #stop}, {@link #resume} and {@link #cancel} refuse with
 * {@link UnsupportedOperationException}; callers wiring the lifecycle endpoints must map that to the contract's 422.
 */
@Component
public class DiscoveryProviderV1Adapter implements DiscoveryProviderAdapter {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryProviderV1Adapter.class);

    private static final Semaphore downloadCertSemaphore = new Semaphore(10);

    private final DiscoveryProperties discoveryProperties;
    private final DiscoveryMessageRepository discoveryMessageRepository;
    private final PlatformTransactionManager transactionManager;
    private final DiscoveryRepository discoveryRepository;
    private final ConnectorRepository connectorRepository;
    private final CertificateRepository certificateRepository;
    private final DiscoveryCertificateRepository discoveryCertificateRepository;
    private final DiscoveryDetailCounts detailCounts;
    private final AttributeEngine attributeEngine;
    private final CertificateHandler certificateHandler;
    private final CredentialInternalService credentialService;
    private final ResourceInternalService resourceService;
    private final ConnectorApiFactory connectorApiFactory;
    private final EventProducer eventProducer;

    public DiscoveryProviderV1Adapter(DiscoveryProperties discoveryProperties,
            PlatformTransactionManager transactionManager, DiscoveryRepository discoveryRepository,
            ConnectorRepository connectorRepository, CertificateRepository certificateRepository,
            DiscoveryCertificateRepository discoveryCertificateRepository, AttributeEngine attributeEngine,
            CertificateHandler certificateHandler, CredentialInternalService credentialService,
            ResourceInternalService resourceService, ConnectorApiFactory connectorApiFactory,
            EventProducer eventProducer, DiscoveryMessageRepository discoveryMessageRepository,
            DiscoveryDetailCounts detailCounts) {
        this.discoveryMessageRepository = discoveryMessageRepository;
        this.detailCounts = detailCounts;
        this.discoveryProperties = discoveryProperties;
        this.transactionManager = transactionManager;
        this.discoveryRepository = discoveryRepository;
        this.connectorRepository = connectorRepository;
        this.certificateRepository = certificateRepository;
        this.discoveryCertificateRepository = discoveryCertificateRepository;
        this.attributeEngine = attributeEngine;
        this.certificateHandler = certificateHandler;
        this.credentialService = credentialService;
        this.resourceService = resourceService;
        this.connectorApiFactory = connectorApiFactory;
        this.eventProducer = eventProducer;
    }

    @Override
    public DiscoveryDetailDto start(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        // reload discovery modal with all association since it could be in separate transaction/session due to async
        DiscoveryContext context = loadDiscoveryContext(discoveryUuid);
        Discovery discovery = context.getDiscovery();
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
                    logger
                            .warn("Could not update metadata for duplicate discovery certificate. Certificate with fingerprint {} not found.",
                                    fingerprint);
                } else {
                    attributeEngine
                            .updateMetadataAttributes(certificate.getMeta(),
                                    ObjectAttributeContentInfo
                                            .builder(Resource.CERTIFICATE, existingCertificate.getUuid())
                                            .connector(UUID.fromString(context.getConnectorDto().getUuid()))
                                            .source(Resource.DISCOVERY, discovery.getUuid())
                                            .sourceName(discovery.getName())
                                            .build());
                }
            } catch (AttributeException e) {
                logger
                        .error("Could not update metadata for duplicate discovery certificate {}.",
                                certificate.getUuid());
            } catch (Exception e) {
                logger
                        .error("Could not parse and process duplicate discovery certificate {}: {}",
                                certificate.getUuid(), e.getMessage());
            }
        }

        context.setCertificatesDiscovered(discoveryCertificateRepository.countByDiscovery(discovery).intValue());
        Long newlyDiscoveredCount = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discovery, true);

        transactionManager.commit(transaction);

        String preProcessingMessage = context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS
                ? null
                : context.getMessage();
        if (newlyDiscoveredCount == 0) {
            if (context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS) {
                context.setDiscoveryStatus(DiscoveryStatus.COMPLETED);
            }
            return finalizeDiscoveryInTx(context, false, preProcessingMessage);
        } else {
            context.setDiscoveryStatus(DiscoveryStatus.PROCESSING);
        }

        updateDiscoveryStateInTx(context, false);

        DiscoveryDetailDto discoveryDto = DiscoveryDtoMapper.toDetailDto(discovery, detailCounts.forRun(discovery));
        eventProducer
                .produceMessage(CertificateDiscoveredEventHandler
                        .constructEventMessage(discovery.getUuid(), context.getLoggedUserUuid(), scheduledJobInfo));
        return discoveryDto;
    }

    @Override
    public void stop(Discovery discovery) {
        throw new UnsupportedOperationException("Stopping a run is not supported by the v1 discovery interface");
    }

    @Override
    public void resume(Discovery discovery) {
        throw new UnsupportedOperationException("Resuming a run is not supported by the v1 discovery interface");
    }

    @Override
    public void cancel(Discovery discovery) {
        throw new UnsupportedOperationException("Cancelling a run is not supported by the v1 discovery interface");
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
        Discovery discovery = discoveryRepository.findWithTriggersByUuid(discoveryUuid);
        try {
            logger.info("Loading discovery context: name={}, uuid={}", discovery.getName(), discovery.getUuid());
            connector = connectorRepository
                    .findByUuid(discovery.getConnectorUuid())
                    .orElseThrow(() -> new NotFoundException(Connector.class, discovery.getConnectorUuid()));
            dataAttributes = attributeEngine
                    .getDefinitionObjectAttributeContent(AttributeType.DATA, connector.getUuid(), null,
                            Resource.DISCOVERY, discovery.getUuid());

            credentialService.loadFullCredentialData(dataAttributes);
            resourceService.loadResourceObjectContentData(dataAttributes);

        } catch (Exception e) {
            message = e.getMessage();
        }

        ConnectorDto connectorDto = connector != null ? connector.mapToDto() : null;
        DiscoveryContext discoveryContext = new DiscoveryContext(loggedUserUuid, connectorDto, discovery,
                dataAttributes);

        if (message != null) {
            discoveryContext.setMessage(message);
            discoveryContext.setDiscoveryStatus(DiscoveryStatus.FAILED);
            discoveryContext.setConnectorDiscoveryStatus(DiscoveryStatus.FAILED);
        }

        transactionManager.commit(transaction);

        return discoveryContext;
    }

    private DiscoveryProviderDto discoverCertificatesByProvider(final DiscoveryContext context)
            throws InterruptedException, DiscoveryException {
        Discovery discovery = context.getDiscovery();

        DiscoveryRequestDto dtoRequest = new DiscoveryRequestDto();
        dtoRequest.setName(discovery.getName());
        dtoRequest.setKind(discovery.getKind());
        dtoRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(context.getDataAttributes()));

        DiscoverySyncApiClient discoveryApiClient = connectorApiFactory
                .getDiscoveryApiClient(context.getConnectorDto());

        // start discovery at provider
        DiscoveryProviderDto response;
        try {
            response = discoveryApiClient.discoverCertificates(context.getConnectorDto(), dtoRequest);
            logger
                    .debug("Discovery start response: name={}, uuid={}, status={}, total={}", discovery.getName(),
                            discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());
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
            logger
                    .debug("Waiting {}ms for discovery to be completed: name={}, uuid={}",
                            discoveryProperties.sleepTimeMs(), discovery.getName(), discovery.getUuid());
            Thread.sleep(discoveryProperties.sleepTimeMs());

            try {
                response = discoveryApiClient
                        .getDiscoveryData(context.getConnectorDto(), getRequest, response.getUuid());
            } catch (ConnectorException e) {
                context.setDiscoveryFailed("Discovery has failed on connector side while waiting for completion");
                throw new DiscoveryException(discovery.getName(), context.getMessage());
            }

            logger
                    .debug("Discovery response: name={}, uuid={}, status={}, total={}", discovery.getName(),
                            discovery.getUuid(), response.getStatus(), response.getTotalCertificatesDiscovered());

            long secondsElapsed = Duration
                    .between(discovery.getStartTime(), OffsetDateTime.now(ZoneOffset.UTC))
                    .toSeconds();
            if (!isReachedMaxTime && secondsElapsed > discoveryProperties.maxWaitTimeSeconds()) {
                isReachedMaxTime = true;

                context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                context.setConnectorDiscoveryStatus(response.getStatus());
                context.setConnectorCertificatesDiscovered(response.getTotalCertificatesDiscovered());
                context
                        .setMessage(
                                "Discovery exceeded maximum time of %d hours. Please abort the discovery if the provider is stuck in state '%s'."
                                        .formatted((int) (discoveryProperties.maxWaitTimeSeconds() / (60 * 60)),
                                                DiscoveryStatus.IN_PROGRESS.getLabel()));
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

    private void downloadDiscoveredCertificates(final DiscoveryContext context, DiscoveryProviderDto response,
            List<DiscoveryProviderCertificateDataDto> duplicateCertificates) throws DiscoveryException {
        int currentPage = 1;
        int currentTotal = 0;
        Discovery discovery = context.getDiscovery();

        DiscoveryDataRequestDto getRequest = new DiscoveryDataRequestDto();
        getRequest.setName(response.getName());
        getRequest.setKind(discovery.getKind());
        getRequest.setPageNumber(1);
        getRequest.setItemsPerPage(discoveryProperties.maxCertificatesPerPage());

        List<Future<?>> futures = new ArrayList<>();
        Set<String> uniqueCertificateContents = new HashSet<>();
        DiscoverySyncApiClient discoveryApiClient = connectorApiFactory
                .getDiscoveryApiClient(context.getConnectorDto());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            while (currentTotal < response.getTotalCertificatesDiscovered()) {
                getRequest.setPageNumber(currentPage);
                getRequest.setItemsPerPage(discoveryProperties.maxCertificatesPerPage());
                try {
                    response = discoveryApiClient
                            .getDiscoveryData(context.getConnectorDto(), getRequest, response.getUuid());
                } catch (ConnectorException e) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context.setMessage("Discovery has failed on connector side while downloading certificates.");
                    throw new DiscoveryException(discovery.getName(), context.getMessage(), e);
                }

                if (response.getCertificateData().isEmpty()) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context
                            .setMessage(String
                                    .format("Retrieved only %d certificates but provider discovered %d certificates in total.",
                                            currentTotal, response.getTotalCertificatesDiscovered()));
                    throw new DiscoveryException(discovery.getName(), context.getMessage());
                }
                if (response.getCertificateData().size() > discoveryProperties.maxCertificatesPerPage()) {
                    handleDiscoveredCertificatesBatch(futures, discovery.getName());
                    context.setDiscoveryStatus(DiscoveryStatus.WARNING);
                    context
                            .setMessage("Too many certificates (%d) in response at page %d. Maximum processable is %d."
                                    .formatted(response.getCertificateData().size(), currentPage,
                                            discoveryProperties.maxCertificatesPerPage()));
                    throw new DiscoveryException(discovery.getName(), context.getMessage());
                }

                futures
                        .add(downloadDiscoveredCertificatesBatchAsync(discovery, response, context.getConnectorDto(),
                                uniqueCertificateContents, duplicateCertificates, executor, currentPage));

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

    private Future<?> downloadDiscoveredCertificatesBatchAsync(final Discovery discovery,
            final DiscoveryProviderDto response, final ConnectorDto connector,
            final Set<String> uniqueCertificateContents,
            final List<DiscoveryProviderCertificateDataDto> duplicateCertificates, final ExecutorService executor,
            final int currentPage) {
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
        certificateHandler
                .updateMetadataDefinition(metadataDefinitions, metadataContentsMapping,
                        UUID.fromString(connector.getUuid()), connector.getName());

        // run in separate virtual thread and continue
        return executor.submit(() -> {
            try {
                logger
                        .trace("Waiting to download batch {} of discovered certificates for discovery {}.", currentPage,
                                discovery.getName());
                downloadCertSemaphore.acquire();
                logger
                        .trace("Downloading batch {} of discovered certificates for discovery {}.", currentPage,
                                discovery.getName());

                // false: a v1 provider's certificate uuid names the certificate, not the occurrence, and nothing
                // in the v1 contract promises it appears once per run.
                certificateHandler
                        .stageDiscoveredCertificates(String.valueOf(currentPage), discovery, discoveredCertificates,
                                false);
                // After the batch commits, so the write needs neither a nested transaction nor a second connection.
                certificateHandler.reportDownloadProgress(discovery);
            } catch (InterruptedException e) {
                logger
                        .error("Downloading batch {} of discovered certificates for discovery {} interrupted.",
                                currentPage, discovery.getName(), e);
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                logger
                        .error("Downloading batch {} of discovered certificates for discovery {} failed.", currentPage,
                                discovery.getName(), e);
            } finally {
                logger
                        .trace("Downloading batch {} of discovered certificates for discovery {} finalized. Released semaphore.",
                                currentPage, discovery.getName());
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
                logger
                        .error("An error occurred during downloading discovered certificate of discovery {}: {}",
                                discoveryName, e.getMessage(), e);
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
        Discovery discovery = updateDiscoveryState(discoveryContext, updateMetadata);
        discoveryRepository.save(discovery);
        transactionManager.commit(transaction);
    }

    private Discovery updateDiscoveryState(DiscoveryContext discoveryContext, boolean updateMetadata) {
        Discovery discovery = discoveryContext.getDiscovery();

        discovery.setStatus(discoveryContext.getDiscoveryStatus());
        discovery.setConnectorStatus(discoveryContext.getConnectorDiscoveryStatus());
        discovery.setMessage(discoveryContext.getMessage());
        discovery.setTotalCertificatesDiscovered(discoveryContext.getCertificatesDiscovered());
        discovery.setConnectorTotalCertificatesDiscovered(discoveryContext.getConnectorCertificatesDiscovered());
        if (updateMetadata && discoveryContext.getMetadata() != null && !discoveryContext.getMetadata().isEmpty()) {
            try {
                attributeEngine
                        .updateMetadataAttributes(discoveryContext.getMetadata(),
                                ObjectAttributeContentInfo
                                        .builder(Resource.DISCOVERY, discovery.getUuid())
                                        .connector(discovery.getConnectorUuid())
                                        .build());
            } catch (Exception e) {
                logger.warn("Failed to serialize discovery metadata");
            }
        }

        return discovery;
    }

    private DiscoveryDetailDto finalizeDiscoveryInTx(DiscoveryContext discoveryContext, boolean updateMetadata,
            String preProcessingMessage) {
        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        Discovery discovery = updateDiscoveryState(discoveryContext, updateMetadata);

        discovery.setEndTime(OffsetDateTime.now(ZoneOffset.UTC));
        if (discovery.getStatus() == DiscoveryStatus.COMPLETED) {
            discovery
                    .setMessage(preProcessingMessage == null
                            ? "Discovery completed successfully"
                            : "Discovery completed. " + preProcessingMessage);
        }

        discoveryRepository.save(discovery);
        transactionManager.commit(transaction);

        DiscoveryDetailDto discoveryDto = DiscoveryDtoMapper.toDetailDto(discovery, detailCounts.forRun(discovery));
        eventProducer
                .produceMessage(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), discoveryContext.getLoggedUserUuid(), null,
                                new DiscoveryResult(discovery.getStatus(), discovery.getMessage())));
        return discoveryDto;
    }

}
