package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.events.handlers.discovery.DiscoveryFailureReason;
import com.otilm.core.events.handlers.discovery.DiscoverySource;
import com.otilm.core.events.transaction.CertificateValidationEvent;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.messaging.model.ValidationMessage;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.ComplianceInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.KeySizeUtil;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.X509ObjectToString;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Service
public class CertificateHandler {

    private static final Logger logger = LoggerFactory.getLogger(CertificateHandler.class);

    private int validationBatchSize;

    private AttributeEngine attributeEngine;
    private ValidationProducer validationProducer;

    private ComplianceInternalService complianceService;
    private CertificateInternalService certificateService;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private CryptographicKeyInternalService cryptographicKeyService;

    private CertificateRepository certificateRepository;
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    private DiscoveryWriter discoveryWriter;
    private TransactionHandler transactionHandler;

    @Autowired
    public void setDiscoveryWriter(DiscoveryWriter discoveryWriter) {
        this.discoveryWriter = discoveryWriter;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setValidationProducer(ValidationProducer validationProducer) {
        this.validationProducer = validationProducer;
    }

    @Value("${certificate.validation.batch-size:10}")
    public void setValidationBatchSize(int validationBatchSize) {
        if (validationBatchSize <= 0) {
            throw new IllegalArgumentException("validationBatchSize must be positive");
        }
        this.validationBatchSize = validationBatchSize;
    }

    @Autowired
    public void setComplianceService(ComplianceInternalService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateEventHistoryService(
            CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Autowired
    public void setCryptographicKeyInternalService(CryptographicKeyInternalService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void validate(Certificate certificate) {
        if (CertificateUtil.isValidationEnabled(certificate, null)) {
            certificateService.validate(certificate);
        }

        try {
            if (certificate.getRaProfileUuid() != null) {
                complianceService.checkResourceObjectComplianceAsSystem(Resource.CERTIFICATE, certificate.getUuid());
            }
        } catch (Exception e) {
            logger
                    .error("Error when checking compliance of certificate {}: {}", certificate.toStringShort(),
                            e.getMessage());
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void updateMetadataDefinition(List<MetadataAttribute> metadataAttributes,
            Map<String, Set<AttributeContent>> metadataContentsMapping, UUID connectorUuid, String connectorName) {
        logger
                .debug("Updating {} discovery certificate metadata definitions for connector {}",
                        metadataAttributes.size(), connectorName);
        for (MetadataAttribute metadataAttribute : metadataAttributes) {
            try {
                AttributeDefinition attributeDefinition = attributeEngine
                        .updateMetadataAttributeDefinition(metadataAttribute, connectorUuid);
                attributeEngine
                        .registerAttributeContentItems(attributeDefinition.getUuid(),
                                metadataContentsMapping.get(metadataAttribute.getUuid()));
            } catch (AttributeException e) {
                logger
                        .error("Unable to update discovery certificate metadata definition with UUID {} and name {} for discovery connector {}. Message: {}",
                                metadataAttribute.getUuid(), metadataAttribute.getName(), connectorName, e.getMessage(),
                                e);
            }
        }
    }

    /**
     * Stages a batch of discovered certificates, the single entry point for both discovery generations. {@code
     * REQUIRED} so it joins whichever caller's transaction is active: v1's own per-batch transaction, or v2's ingestor
     * transaction so staged rows commit together with the cursor advance.
     *
     * @param refsDedupeWithinRun true only for v2: the certificate's {@code uuid} is the connector's per-occurrence
     * key, stored as {@code uniqueRef} and enforced by the run's unique index. A v1 provider uuid names the certificate
     * itself, so it is not stored.
     * @return the shaped reason for each certificate that could not be staged, named by kind rather than by which
     * certificate hit it — v2 files these in the run's message log, where the same reason across a whole run aggregates
     * onto one entry and the certificate that hit it is already in the log above. v1 discards them.
     */
    @Transactional
    public List<String> stageDiscoveredCertificates(String batch, Discovery discovery,
            List<DiscoveryProviderCertificateDataDto> discoveredCertificates, boolean refsDedupeWithinRun) {
        List<String> failures = new ArrayList<>();
        for (DiscoveryProviderCertificateDataDto certificate : discoveredCertificates) {
            DiscoveryCertificate discoveryCertificate = null;
            try {
                X509Certificate x509Cert = CertificateUtil.parseCertificate(certificate.getBase64Content());
                String fingerprint = CertificateUtil.getThumbprint(x509Cert.getEncoded());
                Certificate existingCertificate = certificateRepository.findByFingerprint(fingerprint).orElse(null);

                discoveryCertificate = CertificateUtil.prepareDiscoveryCertificate(existingCertificate, x509Cert);
                discoveryCertificate.setDiscovery(discovery);
                discoveryCertificate.setNewlyDiscovered(existingCertificate == null);
                discoveryCertificate.setMeta(certificate.getMeta());
                if (refsDedupeWithinRun) {
                    discoveryCertificate.setUniqueRef(certificate.getUuid());
                    // The v2 path alone carries these; a v1 provider numbers and timestamps nothing, and the
                    // items listing synthesizes both for such a row at read time.
                    discoveryCertificate.setSequence(certificate.getSequence());
                    discoveryCertificate.setDiscoveredAt(certificate.getDiscoveredAt());
                }

                if (existingCertificate == null) {
                    discoveryCertificate
                            .setCertificateContent(certificateService
                                    .checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Cert)));
                } else {
                    updateDiscoveredCertificate(DiscoverySource.of(discovery), existingCertificate,
                            certificate.getMeta());
                    discoveryCertificate.setProcessed(true);
                }

                discoveryCertificateRepository.save(discoveryCertificate);
            } catch (Exception e) {
                String identifier = discoveryCertificate == null
                        ? certificate.getUuid()
                        : discoveryCertificate.getCommonName();
                logger
                        .error("Unable to create discovery certificate {} in batch {} for discovery {}. Message: {}",
                                identifier, batch, discovery.getName(), e.getMessage(), e);
                failures.add(DiscoveryFailureReason.shape(e));
            }
        }
        return failures;
    }

    /**
     * Called after {@link #stageDiscoveredCertificates} returns: reporting from inside that transaction cost a second
     * pooled connection per batch and held the discovery row's write lock, serialising the batches on it.
     * <p>
     * Failures are swallowed -- progress is cosmetic, and letting one out would have the caller log the batch as
     * failed. Addressed by identifier, not by saving the detached instance every batch holds a copy of.
     */
    public void reportDownloadProgress(Discovery discovery) {
        try {
            Long currentCount = discoveryCertificateRepository.countByDiscovery(discovery);
            String progress = String
                    .format("Downloaded %d %% of discovered certificates from provider (%d / %d)",
                            (int) ((currentCount / (double) discovery.getConnectorTotalCertificatesDiscovered()) * 100),
                            currentCount, discovery.getConnectorTotalCertificatesDiscovered());
            transactionHandler
                    .runInNewTransaction(() -> discoveryWriter.updateProgressMessage(discovery.getUuid(), progress));
        } catch (Exception e) {
            logger
                    .error("Unable to report download progress of discovery {}. Message: {}", discovery.getName(),
                            e.getMessage(), e);
        }
    }

    /**
     * @return true if the key was associated with the certificates, false if the upload was skipped because no
     * committed certificate backs the given UUIDs (see {@link #uploadKeyInternal}). Callers use the result to keep the
     * discovery status visible when key association could not complete.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT,
            rollbackFor = NoSuchAlgorithmException.class)
    public boolean uploadDiscoveredCertificateKey(PublicKey publicKey, List<UUID> certificateUuids)
            throws NoSuchAlgorithmException {
        UUID keyUuid = uploadKeyInternal(publicKey, certificateUuids, "certKey_");
        if (keyUuid == null) {
            return false;
        }
        certificateRepository.setKeyUuid(keyUuid, certificateUuids);
        return true;
    }

    /**
     * @return true if the alternative key was associated with the certificates, false if the upload was skipped because
     * no committed certificate backs the given UUIDs.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT,
            rollbackFor = NoSuchAlgorithmException.class)
    public boolean uploadDiscoveredCertificateAltKey(PublicKey publicKey, List<UUID> certificateUuids)
            throws NoSuchAlgorithmException {
        UUID keyUuid = uploadKeyInternal(publicKey, certificateUuids, "altCertKey_");
        if (keyUuid == null) {
            return false;
        }
        certificateRepository.setAltKeyUuidAndHybridCertificate(keyUuid, certificateUuids);
        return true;
    }

    private UUID uploadKeyInternal(PublicKey publicKey, List<UUID> certificateUuids, String namePrefix)
            throws NoSuchAlgorithmException {
        String fingerprint = CertificateUtil
                .getThumbprint(
                        Base64.getEncoder().encodeToString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));

        // The key can only be associated with committed certificate rows. A null result means none of
        // certificateUuids resolves to a committed certificate (the per-certificate transaction that queued this
        // key rolled back before commit), so there is nothing to associate the key with. Skip regardless of
        // whether a key already exists for this fingerprint, so the skipped association still surfaces in the
        // discovery status rather than looking clean on the shared-key path.
        Certificate firstCertificate = certificateRepository.findFirstByUuidIn(certificateUuids);
        if (firstCertificate == null) {
            logger
                    .warn("No committed certificate found for key with fingerprint {} among UUIDs {}; skipping key upload. The certificate(s) were likely lost to a rolled-back transaction during discovery post-processing.",
                            fingerprint, certificateUuids);
            return null;
        }

        UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
        if (keyUuid == null) {
            String keyName = namePrefix
                    + Objects.requireNonNullElse(firstCertificate.getCommonName(), firstCertificate.getSerialNumber());
            keyUuid = cryptographicKeyService
                    .uploadCertificatePublicKey(keyName, publicKey, KeySizeUtil.getKeyLength(publicKey), fingerprint);
        }
        return keyUuid;
    }

    @Transactional
    public void updateDiscoveredCertificate(DiscoverySource source, Certificate certificate,
            List<MetadataAttribute> metadata) {
        try {
            attributeEngine
                    .updateMetadataAttributes(metadata,
                            ObjectAttributeContentInfo
                                    .builder(Resource.CERTIFICATE, certificate.getUuid())
                                    .connector(source.connectorUuid())
                                    .source(Resource.DISCOVERY, source.discoveryUuid())
                                    .sourceName(source.discoveryName())
                                    .build());
        } catch (AttributeException e) {
            logger.error("Could not update metadata for discovery certificate {}.", certificate.getUuid());
        }
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("Discovery Name", source.discoveryName());
        additionalInfo.put("Discovery UUID", source.discoveryUuid());
        additionalInfo.put("Discovery Connector Name", source.connectorName());
        additionalInfo.put("Discovery Kind", source.discoveryKind());
        certificateEventHistoryService
                .addEventHistory(certificate.getUuid(), CertificateEvent.DISCOVERY, CertificateEventStatus.SUCCESS,
                        "Discovered from Connector: " + source.connectorName() + " via discovery: "
                                + source.discoveryName(),
                        MetaDefinitions.serialize(additionalInfo));
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleCertificateValidationEvent(CertificateValidationEvent event) {
        List<UUID> uuids = event.certificateUuids();
        int size = uuids.size();
        for (int i = 0; i < size; i += validationBatchSize) {
            List<UUID> batch = uuids.subList(i, Math.min(i + validationBatchSize, size));
            validationProducer
                    .produceMessage(new ValidationMessage(Resource.CERTIFICATE, batch, event.discoveryUuid(),
                            event.discoveryName(), event.locationUuid(), event.locationName()));
        }
    }
}
