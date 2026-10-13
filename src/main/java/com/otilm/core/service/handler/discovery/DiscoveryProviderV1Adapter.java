package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.DiscoveryException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
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
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
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
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.model.discovery.DiscoveryContext;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.DiscoveryProperties;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.CertificateUtil;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

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

    private static final String RUN_METADATA_NOT_STORED = "Discovery metadata could not be stored.";

    private static final String CONTEXT_NOT_LOADED = "Discovery could not be prepared in Core.";

    private final DiscoveryProperties discoveryProperties;
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
    private final DiscoveryMessageWriter messageWriter;
    private final TransactionTemplate transactions;
    private final TransactionTemplate readOnlyTransactions;
    private final TransactionTemplate newTransactions;
    private final DiscoveryWriter discoveryWriter;

    public DiscoveryProviderV1Adapter(DiscoveryProperties discoveryProperties,
            PlatformTransactionManager transactionManager, DiscoveryRepository discoveryRepository,
            ConnectorRepository connectorRepository, CertificateRepository certificateRepository,
            DiscoveryCertificateRepository discoveryCertificateRepository, AttributeEngine attributeEngine,
            CertificateHandler certificateHandler, CredentialInternalService credentialService,
            ResourceInternalService resourceService, ConnectorApiFactory connectorApiFactory,
            EventProducer eventProducer, DiscoveryDetailCounts detailCounts, DiscoveryMessageWriter messageWriter,
            DiscoveryWriter discoveryWriter) {
        this.detailCounts = detailCounts;
        this.discoveryProperties = discoveryProperties;
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
        this.messageWriter = messageWriter;
        this.transactions = new TransactionTemplate(transactionManager);
        this.readOnlyTransactions = new TransactionTemplate(transactionManager);
        this.readOnlyTransactions.setReadOnly(true);
        this.newTransactions = new TransactionTemplate(transactionManager);
        this.newTransactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.discoveryWriter = discoveryWriter;
    }

    @Override
    public DiscoveryDetailDto start(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        try {
            return run(discoveryUuid, scheduledJobInfo);
        } catch (RuntimeException e) {
            return endAfterCoreFailure(discoveryUuid, e);
        }
    }

    /**
     * Ends the run as Failed when Core itself could not finish it, so it never stays In progress. The message is fixed
     * text, so no internal detail reaches the user; the exception goes to the log. The ending commits before the detail
     * is read, so a read that fails as well leaves the run ended and rethrows the original failure.
     */
    private DiscoveryDetailDto endAfterCoreFailure(UUID discoveryUuid, RuntimeException failure) {
        logFailure("Discovery {} failed in Core", discoveryUuid, failure);
        String message = "Discovery failed in Core.";
        boolean ended = Boolean.TRUE
                .equals(newTransactions
                        .execute(status -> discoveryWriter.markFailedUnlessEnded(discoveryUuid, message)));
        if (!ended) {
            throw failure;
        }
        eventProducer
                .produceMessage(DiscoveryFinishedEventHandler
                        .constructEventMessage(discoveryUuid, AuthHelper.getActingUserUuidOrNull(), null,
                                new DiscoveryResult(DiscoveryStatus.FAILED, message)));
        try {
            return Objects
                    .requireNonNull(newTransactions
                            .execute(status -> discoveryRepository
                                    .findByUuid(discoveryUuid)
                                    .map(run -> DiscoveryDtoMapper.toDetailDto(run, detailCounts.forRun(run)))
                                    .orElseThrow()));
        } catch (RuntimeException detailFailure) {
            failure.addSuppressed(detailFailure);
            throw failure;
        }
    }

    private DiscoveryDetailDto run(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        // reload discovery modal with all association since it could be in separate transaction/session due to async
        DiscoveryContext context = loadDiscoveryContext(discoveryUuid);
        Discovery discovery = context.getDiscovery();
        if (context.getDiscoveryStatus() == DiscoveryStatus.FAILED) {
            return finalizeDiscoveryInTx(context, null);
        }

        // discover certificates by provider
        DiscoveryProviderDto providerResponse;
        try {
            providerResponse = discoverCertificatesByProvider(context);
        } catch (DiscoveryException e) {
            logFailure("Discovery {} did not complete at the provider", discoveryUuid, e);
            storeRunMetadata(context);
            return finalizeDiscoveryInTx(context, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failAtProvider(context, e);
        } catch (RuntimeException e) {
            return failAtProvider(context, e);
        }
        storeRunMetadata(context);
        if (context.getConnectorCertificatesDiscovered() == 0) {
            context.setDiscoveryStatus(DiscoveryStatus.COMPLETED);
            return finalizeDiscoveryInTx(context, "No certificates discovered at provider");
        }
        updateDiscoveryStateInTx(context);

        // download and create discovered certificates
        List<DiscoveryProviderCertificateDataDto> duplicateCertificates = new ArrayList<>();
        try {
            downloadDiscoveredCertificates(context, providerResponse, duplicateCertificates);
            context.setDiscoveryStatus(DiscoveryStatus.IN_PROGRESS);
            context.setMessage("Discovered certificates downloaded from provider");
        } catch (DiscoveryException e) {
            logFailure("Discovery {} could not download all certificates", discoveryUuid, e);
        }

        // Each duplicate's metadata is written in a transaction of its own, so one that fails cannot take the counts
        // down with it.
        for (DiscoveryProviderCertificateDataDto certificate : duplicateCertificates) {
            try {
                transactions.executeWithoutResult(status -> updateDuplicateCertificateMetadata(context, certificate));
            } catch (RuntimeException e) {
                logger
                        .error("Could not update metadata of duplicate certificate {} of discovery {}",
                                certificate.getUuid(), discovery.getName(), e);
            }
        }

        StagedCounts counts = Objects
                .requireNonNull(readOnlyTransactions
                        .execute(status -> new StagedCounts(
                                discoveryCertificateRepository.countByDiscovery(discovery).intValue(),
                                discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discovery, true))));
        context.setCertificatesDiscovered(counts.certificates());
        long newlyDiscoveredCount = counts.newlyDiscovered();

        String preProcessingMessage = context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS
                ? null
                : context.getMessage();
        if (newlyDiscoveredCount == 0) {
            if (context.getDiscoveryStatus() == DiscoveryStatus.IN_PROGRESS) {
                context.setDiscoveryStatus(DiscoveryStatus.COMPLETED);
            }
            return finalizeDiscoveryInTx(context, preProcessingMessage);
        } else {
            context.setDiscoveryStatus(DiscoveryStatus.PROCESSING);
        }

        updateDiscoveryStateInTx(context);

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

        // reload discovery modal with all association since it could be in separate transaction/session due to async
        Discovery discovery = Objects
                .requireNonNull(readOnlyTransactions
                        .execute(status -> discoveryRepository.findWithTriggersByUuid(discoveryUuid)));
        try {
            return Objects
                    .requireNonNull(
                            readOnlyTransactions.execute(status -> loadConnectedContext(loggedUserUuid, discovery)));
        } catch (RuntimeException e) {
            // Out here, so the template has rolled back: a runtime failure that crossed a transactional service has
            // marked it rollback-only, and handling it inside would turn into an UnexpectedRollbackException on commit.
            logFailure("Could not load the context of discovery {}", discoveryUuid, e);
            return failedContext(loggedUserUuid, null, discovery, PlatformException.safeMessage(e, CONTEXT_NOT_LOADED));
        }
    }

    /** Checked failures do not mark the transaction rollback-only, so they are answered here, inside it. */
    private DiscoveryContext loadConnectedContext(UUID loggedUserUuid, Discovery discovery) {
        Connector connector = null;
        List<DataAttribute> dataAttributes = null;
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
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            logFailure("Could not load the context of discovery {}", discovery.getUuid(), e);
            ConnectorDto connectorDto = connector != null ? connector.mapToDto() : null;
            return failedContext(loggedUserUuid, connectorDto, discovery, safeReason(e, CONTEXT_NOT_LOADED));
        }
        return new DiscoveryContext(loggedUserUuid, connector.mapToDto(), discovery, dataAttributes);
    }

    private static DiscoveryContext failedContext(UUID loggedUserUuid, ConnectorDto connectorDto, Discovery discovery,
            String message) {
        DiscoveryContext context = new DiscoveryContext(loggedUserUuid, connectorDto, discovery, null);
        context.setMessage(message);
        context.setDiscoveryStatus(DiscoveryStatus.FAILED);
        context.setConnectorDiscoveryStatus(DiscoveryStatus.FAILED);
        return context;
    }

    private DiscoveryDetailDto failAtProvider(DiscoveryContext context, Exception e) {
        logFailure("Error in discovery '{}' at provider", context.getDiscovery().getName(), e);
        context
                .setDiscoveryFailed(e instanceof InterruptedException
                        ? "Discovery was interrupted."
                        : withSafeReason("Error in provider during discovery", e));
        storeRunMetadata(context);
        return finalizeDiscoveryInTx(context, null);
    }

    /**
     * Logs a failure with its stack, unless a connector answer Core could not parse is in its chain: Jackson quotes
     * that answer in its message, which can carry key or secret material, so only the types are logged, as
     * BaseApiClient logs them.
     */
    private static void logFailure(String message, Object subject, Throwable failure) {
        if (ExceptionUtils.indexOfType(failure, JsonProcessingException.class) >= 0) {
            logger
                    .error(message + "; failure types: {}", subject,
                            ExceptionUtils
                                    .getThrowableList(failure)
                                    .stream()
                                    .map(t -> t.getClass().getName())
                                    .collect(Collectors.joining(" <- ")));
        } else {
            logger.error(message, subject, failure);
        }
    }

    /** The reason is shown to users, so it is the exception's own text only when that is safe to show. */
    private static String withSafeReason(String prefix, Exception e) {
        String reason = safeReason(e, "");
        return reason.isBlank() ? prefix + "." : prefix + ": " + reason;
    }

    /**
     * The exception's own text when Core wrote it, otherwise the fallback. A {@link ConnectorException} is a
     * {@link PlatformException}, but its message is the connector's response body, so it stays in the log.
     */
    private static String safeReason(Exception e, String fallback) {
        return e instanceof ConnectorException ? fallback : PlatformException.safeMessage(e, fallback);
    }

    private record StagedCounts(int certificates, long newlyDiscovered) {
    }

    /** Runs in the caller's transaction; a checked failure is rethrown unchecked so the transaction rolls back. */
    private void updateDuplicateCertificateMetadata(DiscoveryContext context,
            DiscoveryProviderCertificateDataDto certificate) {
        Discovery discovery = context.getDiscovery();
        try {
            X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate.getBase64Content());
            String fingerprint = CertificateUtil.getThumbprint(x509Cert.getEncoded());
            Certificate existingCertificate = certificateRepository.findByFingerprint(fingerprint).orElse(null);
            if (existingCertificate == null) {
                logger
                        .warn("Could not update metadata for duplicate discovery certificate. Certificate with fingerprint {} not found.",
                                fingerprint);
                return;
            }
            attributeEngine
                    .updateMetadataAttributes(certificate.getMeta(),
                            ObjectAttributeContentInfo
                                    .builder(Resource.CERTIFICATE, existingCertificate.getUuid())
                                    .connector(UUID.fromString(context.getConnectorDto().getUuid()))
                                    .source(Resource.DISCOVERY, discovery.getUuid())
                                    .sourceName(discovery.getName())
                                    .build());
        } catch (AttributeException | GeneralSecurityException e) {
            throw new MetadataNotStored(e);
        }
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
            logFailure("Discovery {} could not be started at the provider", discovery.getUuid(), e);
            context.setDiscoveryFailed(withSafeReason("Failed to run discovery at the provider", e));
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
                updateDiscoveryStateInTx(context);
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

    private void updateDiscoveryStateInTx(DiscoveryContext discoveryContext) {
        transactions.executeWithoutResult(status -> discoveryRepository.save(updateDiscoveryState(discoveryContext)));
    }

    private Discovery updateDiscoveryState(DiscoveryContext discoveryContext) {
        Discovery discovery = discoveryContext.getDiscovery();

        discovery.setStatus(discoveryContext.getDiscoveryStatus());
        discovery.setConnectorStatus(discoveryContext.getConnectorDiscoveryStatus());
        discovery.setMessage(withRunMetadataNote(discoveryContext, discoveryContext.getMessage()));
        discovery.setTotalCertificatesDiscovered(discoveryContext.getCertificatesDiscovered());
        discovery.setConnectorTotalCertificatesDiscovered(discoveryContext.getConnectorCertificatesDiscovered());
        return discovery;
    }

    /**
     * Stores the metadata the connector reported about the run, once, in a transaction of its own. It is advisory: a
     * failure, a checked refusal included (rethrown unchecked inside the transaction), takes back whatever was written,
     * leaves the run's outcome alone, and stays on the run as a warning that no later message replaces.
     */
    private void storeRunMetadata(DiscoveryContext context) {
        if (context.isRunMetadataHandled()) {
            return;
        }
        context.setRunMetadataHandled(true);
        List<MetadataAttribute> metadata = context.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return;
        }
        Discovery discovery = context.getDiscovery();
        ObjectAttributeContentInfo target = ObjectAttributeContentInfo
                .builder(Resource.DISCOVERY, discovery.getUuid())
                .connector(discovery.getConnectorUuid())
                .build();
        try {
            newTransactions.executeWithoutResult(status -> {
                try {
                    attributeEngine.updateMetadataAttributes(metadata, target);
                } catch (AttributeException e) {
                    throw new MetadataNotStored(e);
                }
            });
        } catch (RuntimeException e) {
            Throwable cause = e instanceof MetadataNotStored ? e.getCause() : e;
            logger.warn("Metadata of discovery {} could not be stored", discovery.getUuid(), cause);
            context.setRunMetadataNotStored(true);
            messageWriter
                    .append(discovery.getUuid(), DiscoveryMessageSeverity.WARNING,
                            DiscoveryMessageCode.RUN_METADATA_NOT_RECORDED,
                            "The connector's metadata about the run could not be stored.");
        }
    }

    private static String withRunMetadataNote(DiscoveryContext context, String message) {
        if (!context.isRunMetadataNotStored()) {
            return message;
        }
        if (message == null || message.isBlank()) {
            return RUN_METADATA_NOT_STORED;
        }
        if (message.endsWith(RUN_METADATA_NOT_STORED)) {
            return message;
        }
        return message.endsWith(".")
                ? message + " " + RUN_METADATA_NOT_STORED
                : message + ". " + RUN_METADATA_NOT_STORED;
    }

    private DiscoveryDetailDto finalizeDiscoveryInTx(DiscoveryContext discoveryContext, String preProcessingMessage) {
        Discovery discovery = discoveryContext.getDiscovery();
        transactions.executeWithoutResult(status -> {
            updateDiscoveryState(discoveryContext);
            discovery.setEndTime(OffsetDateTime.now(ZoneOffset.UTC));
            if (discovery.getStatus() == DiscoveryStatus.COMPLETED) {
                discovery
                        .setMessage(withRunMetadataNote(discoveryContext,
                                preProcessingMessage == null
                                        ? "Discovery completed successfully"
                                        : "Discovery completed. " + preProcessingMessage));
            }
            discoveryRepository.save(discovery);
        });

        DiscoveryDetailDto discoveryDto = DiscoveryDtoMapper.toDetailDto(discovery, detailCounts.forRun(discovery));
        eventProducer
                .produceMessage(DiscoveryFinishedEventHandler
                        .constructEventMessage(discovery.getUuid(), discoveryContext.getLoggedUserUuid(), null,
                                new DiscoveryResult(discovery.getStatus(), discovery.getMessage())));
        return discoveryDto;
    }

    /** Carries a checked failure out of a transaction callback, rolling the transaction back on the way. */
    private static final class MetadataNotStored extends RuntimeException implements PlatformException {
        private MetadataNotStored(Exception cause) {
            super(cause);
        }
    }

}
