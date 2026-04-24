package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.EventException;
import com.czertainly.api.model.common.events.data.CertificateDiscoveredEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.DiscoveryCertificate;
import com.czertainly.core.dao.entity.DiscoveryHistory;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerAssociation;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.DiscoveryCertificateRepository;
import com.czertainly.core.dao.repository.DiscoveryRepository;
import com.czertainly.core.evaluator.CertificateTriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.EventContextTriggers;
import com.czertainly.core.events.EventHandler;
import com.czertainly.core.events.data.DiscoveryResult;
import com.czertainly.core.events.transaction.TransactionHandler;
import com.czertainly.core.messaging.jms.producers.ValidationProducer;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.messaging.model.ValidationMessage;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.handler.CertificateHandler;
import com.czertainly.core.tasks.ScheduledJobInfo;
import com.czertainly.core.util.CertificateUtil;
import com.pivovarit.collectors.ParallelCollectors;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

@Transactional
@Component(ResourceEvent.Codes.CERTIFICATE_DISCOVERED)
public class CertificateDiscoveredEventHandler extends EventHandler<Certificate> {

    private static final Integer MAXIMUM_PARALLELISM = 5;
    private static final Logger logger = LoggerFactory.getLogger(CertificateDiscoveredEventHandler.class);

    private static final Semaphore processCertSemaphore = new Semaphore(10);

    private CertificateHandler certificateHandler;
    private TransactionHandler transactionHandler;
    private ValidationProducer validationProducer;

    private CertificateService certificateService;
    private DiscoveryRepository discoveryRepository;
    private DiscoveryCertificateRepository discoveryCertificateRepository;

    @Autowired
    protected CertificateDiscoveredEventHandler(CertificateRepository repository, CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
    }

    @Autowired
    public void setDiscoveryCertificateHandler(CertificateHandler certificateHandler) {
        this.certificateHandler = certificateHandler;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setValidationProducer(ValidationProducer validationProducer) {
        this.validationProducer = validationProducer;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setDiscoveryRepository(DiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Override
    protected EventContext<Certificate> prepareContext(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = new EventContext<>(eventMessage, triggerEvaluator, null, null);
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones

        return context;
    }

    @Override
    protected Object getEventData(Certificate certificate, Object eventMessageData) {
        CertificateDiscoveredEventData eventData = new CertificateDiscoveredEventData();
        eventData.setCertificateUuid(certificate.getUuid());
        eventData.setFingerprint(certificate.getFingerprint());
        eventData.setSerialNumber(certificate.getSerialNumber());
        eventData.setSubjectDn(certificate.getSubjectDn());
        eventData.setIssuerDn(certificate.getIssuerDn());
        eventData.setNotBefore(certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
        eventData.setExpiresAt(certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));

        return eventData;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void handleEvent(EventMessage eventMessage) throws EventException {
        if (eventMessage.getOverrideResource() == null || eventMessage.getOverrideObjectUuid() == null) {
            throw new EventException(eventMessage.getEvent(), "Event currently supported only through discovery as overriding resource");
        }

        // merge platform and discovery triggers to process them together, first discovery one and then platform
        EventContext<Certificate> context = prepareContext(eventMessage);
        EventContextTriggers discoveryTriggers = fetchEventTriggers(context, eventMessage.getOverrideResource(), eventMessage.getOverrideObjectUuid());
        List<TriggerAssociation> mergedTriggers = new ArrayList<>(discoveryTriggers.getTriggers());
        List<TriggerAssociation> mergedIgnoreTriggers = new ArrayList<>(discoveryTriggers.getIgnoreTriggers());
        mergedTriggers.addAll(context.getPlatformTriggers().getTriggers());
        mergedIgnoreTriggers.addAll(context.getPlatformTriggers().getIgnoreTriggers());

        // Get newly discovered certificates
        DiscoveryHistory discovery = discoveryRepository.findByUuid(eventMessage.getOverrideObjectUuid()).orElseThrow(() -> new EventException(eventMessage.getEvent(), "Discovery with UUID %s not found".formatted(eventMessage.getOverrideObjectUuid())));
        String originalMessage = discovery.getStatus() != DiscoveryStatus.IN_PROGRESS ? discovery.getMessage() : null;
        List<DiscoveryCertificate> discoveredCertificates = discoveryCertificateRepository.findByDiscoveryUuidAndNewlyDiscovered(eventMessage.getOverrideObjectUuid(), true, Pageable.unpaged());
        logger.debug("Going to process {} triggers on {} discovered certificates", mergedIgnoreTriggers.size() + mergedTriggers.size(), context.getResourceObjects().size());

        if (discoveredCertificates.isEmpty()) {
            eventProducer.produceMessage(DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), context.getUserUuid(), context.getScheduledJobInfo(), new DiscoveryResult(DiscoveryStatus.PROCESSING, originalMessage)));
            return;
        }

        // For each discovered certificate and for each found trigger, check if it satisfies rules defined by the trigger and perform actions accordingly
        AtomicInteger index = new AtomicInteger(0);
        ConcurrentMap<PublicKey, List<UUID>> keyToCertificates = new ConcurrentHashMap<>();
        ConcurrentMap<PublicKey, List<UUID>> altKeyToCertificates = new ConcurrentHashMap<>();
        try (ExecutorService virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor()) {
            SecurityContext securityContext = SecurityContextHolder.getContext();
            DelegatingSecurityContextExecutor executor = new DelegatingSecurityContextExecutor(virtualThreadExecutor, securityContext);
            CompletableFuture<Stream<Object>> future = discoveredCertificates.stream().collect(
                    ParallelCollectors.parallel(
                            discoveryCertificate -> {
                                int certIndex;
                                try {
                                    certIndex = index.incrementAndGet();
                                    processCertSemaphore.acquire();
                                    transactionHandler.runInNewTransaction(() -> processDiscoveredCertificate(context, mergedIgnoreTriggers, mergedTriggers, certIndex, discoveredCertificates.size(), discovery, discoveryCertificate, keyToCertificates, altKeyToCertificates));
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                    logger.error("Thread {} processing cert {} of discovered certificates interrupted.", Thread.currentThread().getName(), index.get());
                                } catch (Exception e) {
                                    logger.error("Unable to process certificate {}: {}", discoveryCertificate.getCommonName(), e.getMessage(), e);
                                } finally {
                                    logger.trace("Thread {} processing cert {} of discovered certificates finalized. Released semaphore.", Thread.currentThread().getName(), index.get());
                                    processCertSemaphore.release();
                                }
                                return null; // Return null to satisfy the return type
                            },
                            executor,
                            MAXIMUM_PARALLELISM
                    )
            );

            // Wait for all tasks to complete
            future.join();
        }

        // Upload certificate keys out of parallel processing to avoid collisions
        for (Map.Entry<PublicKey, List<UUID>> entry : keyToCertificates.entrySet()) {
            try {
                certificateHandler.uploadDiscoveredCertificateKey(entry.getKey(), entry.getValue());
            } catch (NoSuchAlgorithmException e) {
                logger.error("Could not create public key for certificates with UUIDs {}: {}", e.getMessage(), entry.getValue());
            }
        }

        for (Map.Entry<PublicKey, List<UUID>> entry : altKeyToCertificates.entrySet()) {
            try {
                certificateHandler.uploadDiscoveredCertificateAltKey(entry.getKey(), entry.getValue());
            } catch (NoSuchAlgorithmException e) {
                logger.error("Could not create alternative public key for certificates with UUIDs {}: {}", e.getMessage(), entry.getValue());
            }
        }

        // trigger other events
        eventProducer.produceMessage(DiscoveryFinishedEventHandler.constructEventMessage(discovery.getUuid(), context.getUserUuid(), context.getScheduledJobInfo(), new DiscoveryResult(DiscoveryStatus.PROCESSING, originalMessage)));
        validationProducer.produceMessage(new ValidationMessage(Resource.CERTIFICATE, null, discovery.getUuid(), discovery.getName(), null, null));
    }

    private void processDiscoveredCertificate(EventContext<Certificate> eventContext, List<TriggerAssociation> mergedIgnoreTriggers, List<TriggerAssociation> mergedTriggers, int certIndex, int totalCount, DiscoveryHistory discovery, DiscoveryCertificate discoveryCertificate, ConcurrentMap<PublicKey, List<UUID>> keysToCertificatesMap,
                                              ConcurrentMap<PublicKey, List<UUID>> altKeysToCertificatesMap) {
        // Get X509 from discovered certificate and create certificate entity, do not save in database yet
        Certificate certificate;
        X509Certificate x509Cert;
        try {
            x509Cert = CertificateUtil.parseCertificate(discoveryCertificate.getCertificateContent().getContent());
            certificate = certificateService.createCertificateEntity(x509Cert);
        } catch (Exception e) {
            logger.error("Unable to create certificate from discovery certificate with UUID {}: {}", discoveryCertificate.getUuid(), e.getMessage());
            discoveryCertificate.setProcessed(true);
            discoveryCertificate.setProcessedError("Unable to create certificate entity: " + e.getMessage());
            discoveryCertificateRepository.save(discoveryCertificate);
            return;
        }

        try {
            List<TriggerHistory> triggerHistories = new ArrayList<>();

            boolean isIgnored = false;
            for (TriggerAssociation triggerAssociation : mergedIgnoreTriggers) {
                Trigger trigger = triggerAssociation.getTrigger();
                TriggerHistory triggerHistory = eventContext.getTriggerEvaluator().evaluateTrigger(trigger, triggerAssociation, certificate, discoveryCertificate.getUuid(), null);
                triggerHistories.add(triggerHistory);
                if (triggerHistory.isActionsPerformed()) {
                    isIgnored = true;
                    break;
                }
            }

            // If some trigger ignored this certificate, certificate is not saved and continue with next one
            if (!isIgnored) { // certificate was not ignored
                // Save certificate to database
                certificateService.updateCertificateEntity(certificate);
                // update objectUuid of not ignored certs
                for (TriggerHistory ignoreTriggerHistory : triggerHistories) {
                    ignoreTriggerHistory.setObjectUuid(certificate.getUuid());
                }

                // Evaluate rest of the triggers in given order
                CertificateDiscoveredEventData eventData = (CertificateDiscoveredEventData) getEventData(certificate, eventContext.getData());
                eventData.setDiscoveryUuid(discovery.getUuid());
                eventData.setDiscoveryName(discovery.getName());
                eventData.setDiscoveryUserUuid(eventContext.getUserUuid());
                eventData.setDiscoveryConnectorUuid(discovery.getConnectorUuid());
                eventData.setDiscoveryConnectorName(discovery.getConnectorName());

                for (TriggerAssociation triggerAssociation : mergedTriggers) {
                    // Create trigger history entry
                    Trigger trigger = triggerAssociation.getTrigger();
                    eventContext.getTriggerEvaluator().evaluateTrigger(trigger, triggerAssociation, certificate, discoveryCertificate.getUuid(), eventData);
                }

                certificateHandler.updateDiscoveredCertificate(discovery, certificate, discoveryCertificate.getMeta());
                keysToCertificatesMap.computeIfAbsent(x509Cert.getPublicKey(), k -> new ArrayList<>()).add(certificate.getUuid());
                byte[] altPublicKey = x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
                if (altPublicKey != null) {
                    addEntryToAltPublicKeyMap(altKeysToCertificatesMap, altPublicKey, certificate);
                }
            }
        } catch (Exception e) {
            logger.error("Unable to process trigger on certificate {} from discovery certificate with UUID {}. Message: {}", certificate.getUuid(), discoveryCertificate.getUuid(), e.getMessage());
        }

        discoveryCertificate.setProcessed(true);
        discoveryCertificateRepository.save(discoveryCertificate);

        // report progress
        if (certIndex % MAXIMUM_PARALLELISM == 0) {
            Long currentCount = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscoveredAndProcessed(discovery, true, true);
            discovery.setMessage(String.format("Processed %d %% of newly discovered certificates (%d / %d)", (int) ((currentCount / (double) totalCount) * 100), currentCount, totalCount));
            discoveryRepository.save(discovery);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Finalize processing discovered certificate: {}", certificate.toStringShort());
        }
    }

    private static void addEntryToAltPublicKeyMap(ConcurrentMap<PublicKey, List<UUID>> altKeysToCertificatesMap, byte[] altPublicKey, Certificate certificate) {
        try {
            altKeysToCertificatesMap.computeIfAbsent(CertificateUtil.getAltPublicKey(altPublicKey), k -> new ArrayList<>()).add(certificate.getUuid());
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Could not parse alternative public key of certificate with UUID {}: {}", certificate.getUuid(), e.getMessage());
        }
    }

    public static EventMessage constructEventMessage(UUID discoveryUuid, UUID userUuid, ScheduledJobInfo scheduledJobInfo) {
        return new EventMessage(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, null, Resource.DISCOVERY, discoveryUuid, null, userUuid, scheduledJobInfo);
    }
}
