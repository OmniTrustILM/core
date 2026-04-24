package com.czertainly.core.service.handler;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.model.common.attribute.common.AttributeContent;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.DiscoveryCertificateRepository;
import com.czertainly.core.dao.repository.DiscoveryRepository;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.messaging.jms.producers.ValidationProducer;
import com.czertainly.core.messaging.model.ValidationMessage;
import com.czertainly.core.service.*;
import com.czertainly.core.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
@Transactional
public class CertificateHandler {

    private static final Logger logger = LoggerFactory.getLogger(CertificateHandler.class);

    private AttributeEngine attributeEngine;
    private ValidationProducer validationProducer;

    private ComplianceService complianceService;
    private CertificateService certificateService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private CryptographicKeyService cryptographicKeyService;

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

    @Autowired
    public void setComplianceService(ComplianceService complianceService) {
        this.complianceService = complianceService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
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
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
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
        certificateRepository.setKeyUuid(keyUuid, certificateUuids);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.DEFAULT)
    public void uploadDiscoveredCertificateAltKey(PublicKey publicKey, List<UUID> certificateUuids) throws NoSuchAlgorithmException {
        UUID keyUuid = uploadKeyInternal(publicKey, certificateUuids, "altCertKey_");
        certificateRepository.setAltKeyUuidAndHybridCertificate(keyUuid, certificateUuids);
    }

    private UUID uploadKeyInternal(PublicKey publicKey, List<UUID> certificateUuids, String namePrefix) throws NoSuchAlgorithmException {
        String fingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
        UUID keyUuid = cryptographicKeyService.findKeyByFingerprint(fingerprint);
        Certificate firstCertificate = certificateRepository.findFirstByUuidIn(certificateUuids);
        if (keyUuid == null) {
            keyUuid = cryptographicKeyService.uploadCertificatePublicKey(namePrefix + firstCertificate.getCommonName(), publicKey, KeySizeUtil.getKeyLength(publicKey), fingerprint);
        }
        return keyUuid;
    }

    public void updateDiscoveredCertificate(DiscoveryHistory discovery, Certificate certificate, List<MetadataAttribute> metadata) {
        // Set metadata attributes, create certificate event history entry and validate certificate
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
        ValidationMessage validationMessage = new ValidationMessage(Resource.CERTIFICATE, event.certificateUuids(), event.discoveryUuid(), event.discoveryName(), event.locationUuid(), event.locationName());
        validationProducer.produceMessage(validationMessage);
    }
}
