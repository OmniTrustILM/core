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
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryHistory;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.CertificateValidationEvent;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.messaging.model.ValidationMessage;
import com.otilm.core.service.*;
import com.otilm.core.util.*;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.ComplianceInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.KeySizeUtil;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.X509ObjectToString;
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

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

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
    private DiscoveryRepository discoveryRepository;
    private DiscoveryCertificateRepository discoveryCertificateRepository;

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
        if (validationBatchSize <= 0) throw new IllegalArgumentException("validationBatchSize must be positive");
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
    public void setCertificateEventHistoryService(CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setDiscoveryRepository(DiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
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
            logger.error("Error when checking compliance of certificate {}: {}", certificate.toStringShort(), e.getMessage());
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void updateMetadataDefinition(List<MetadataAttribute> metadataAttributes, Map<String, Set<AttributeContent>> metadataContentsMapping, UUID connectorUuid, String connectorName) {
        logger.debug("Updating {} discovery certificate metadata definitions for connector {}", metadataAttributes.size(), connectorName);
        for (MetadataAttribute metadataAttribute : metadataAttributes) {
            try {
                AttributeDefinition attributeDefinition = attributeEngine.updateMetadataAttributeDefinition(metadataAttribute, connectorUuid);
                attributeEngine.registerAttributeContentItems(attributeDefinition.getUuid(), metadataContentsMapping.get(metadataAttribute.getUuid()));
            } catch (AttributeException e) {
                logger.error("Unable to update discovery certificate metadata definition with UUID {} and name {} for discovery connector {}. Message: {}", metadataAttribute.getUuid(), metadataAttribute.getName(), connectorName, e.getMessage(), e);
            }
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void createDiscoveredCertificate(String batch, DiscoveryHistory discovery, List<DiscoveryProviderCertificateDataDto> discoveredCertificates) {
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

                if (existingCertificate == null) {
                    discoveryCertificate.setCertificateContent(certificateService.checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Cert)));
                } else {
                    updateDiscoveredCertificate(discovery, existingCertificate, certificate.getMeta());
                    discoveryCertificate.setProcessed(true);
                }

                discoveryCertificateRepository.save(discoveryCertificate);
            } catch (Exception e) {
                logger.error("Unable to create discovery certificate {} in batch {} for discovery {}. Message: {}", discoveryCertificate == null ? certificate.getUuid() : discoveryCertificate.getCommonName(), batch, discovery.getName(), e.getMessage(), e);
            }
        }

        // report progress
        Long currentCount = discoveryCertificateRepository.countByDiscovery(discovery);
        discovery.setMessage(String.format("Downloaded %d %% of discovered certificates from provider (%d / %d)", (int) ((currentCount / (double) discovery.getConnectorTotalCertificatesDiscovered()) * 100), currentCount, discovery.getConnectorTotalCertificatesDiscovered()));
        discoveryRepository.save(discovery);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void uploadDiscoveredCertificateKey(PublicKey publicKey, List<UUID> certificateUuids) throws NoSuchAlgorithmException {
        UUID keyUuid = uploadKeyInternal(publicKey, certificateUuids, "certKey_");
        if (keyUuid != null) {
            certificateRepository.setKeyUuid(keyUuid, certificateUuids);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void uploadDiscoveredCertificateAltKey(PublicKey publicKey, List<UUID> certificateUuids) throws NoSuchAlgorithmException {
        UUID keyUuid = uploadKeyInternal(publicKey, certificateUuids, "altCertKey_");
        if (keyUuid != null) {
            certificateRepository.setAltKeyUuidAndHybridCertificate(keyUuid, certificateUuids);
        }
    }

    private UUID uploadKeyInternal(PublicKey publicKey, List<UUID> certificateUuids, String namePrefix) throws NoSuchAlgorithmException {
        String fingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
        UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
        if (keyUuid != null) {
            return keyUuid;
        }

        // A key is uploaded only if none already exists for this fingerprint; the certificate is fetched
        // solely to name the new key. A null result means none of certificateUuids resolves to a committed
        // certificate row (the per-certificate transaction that queued this key rolled back before commit),
        // so there is nothing to associate the key with. Skip the upload instead of dereferencing null.
        Certificate firstCertificate = certificateRepository.findFirstByUuidIn(certificateUuids);
        if (firstCertificate == null) {
            logger.warn("No committed certificate found for key with fingerprint {} among UUIDs {}; skipping key upload. The certificate(s) were likely lost to a rolled-back transaction during discovery post-processing.", fingerprint, certificateUuids);
            return null;
        }

        String keyName = namePrefix + Objects.requireNonNullElse(firstCertificate.getCommonName(), firstCertificate.getSerialNumber());
        return cryptographicKeyService.uploadCertificatePublicKey(keyName, publicKey, KeySizeUtil.getKeyLength(publicKey), fingerprint);
    }

    @Transactional
    public void updateDiscoveredCertificate(DiscoveryHistory discovery, Certificate certificate, List<MetadataAttribute> metadata) {
        try {
            attributeEngine.updateMetadataAttributes(metadata, ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, certificate.getUuid()).connector(discovery.getConnectorUuid()).source(Resource.DISCOVERY, discovery.getUuid()).sourceName(discovery.getName()).build());
        } catch (AttributeException e) {
            logger.error("Could not update metadata for discovery certificate {}.", certificate.getUuid());
        }
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("Discovery Name", discovery.getName());
        additionalInfo.put("Discovery UUID", discovery.getUuid());
        additionalInfo.put("Discovery Connector Name", discovery.getConnectorName());
        additionalInfo.put("Discovery Kind", discovery.getKind());
        certificateEventHistoryService.addEventHistory(
                certificate.getUuid(),
                CertificateEvent.DISCOVERY,
                CertificateEventStatus.SUCCESS,
                "Discovered from Connector: " + discovery.getConnectorName() + " via discovery: " + discovery.getName(),
                MetaDefinitions.serialize(additionalInfo)
        );
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleCertificateValidationEvent(CertificateValidationEvent event) {
        List<UUID> uuids = event.certificateUuids();
        int size = uuids.size();
        for (int i = 0; i < size; i += validationBatchSize) {
            List<UUID> batch = uuids.subList(i, Math.min(i + validationBatchSize, size));
            validationProducer.produceMessage(new ValidationMessage(Resource.CERTIFICATE, batch,
                    event.discoveryUuid(), event.discoveryName(), event.locationUuid(), event.locationName()));
        }
    }
}
