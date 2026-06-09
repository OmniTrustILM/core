package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.model.ValidationMessage;
import com.otilm.core.service.handler.CertificateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ValidationListener implements MessageProcessor<ValidationMessage> {

    private static final Logger logger = LoggerFactory.getLogger(ValidationListener.class);

    private CertificateRepository certificateRepository;

    private CertificateHandler certificateHandler;

    @Override
    public void processMessage(final ValidationMessage validationMessage) {
        List<Certificate> certificates;
        if (validationMessage.getUuids() != null) {
            certificates = certificateRepository.findAllWithAssociationsByUuidIn(validationMessage.getUuids());

            logger.debug("Validating {} certificate(s)", certificates.size());
            int certificatesValidated = 0;
            for (Certificate certificate : certificates) {
                certificateHandler.validate(certificate);
                if (certificate.getValidationStatus() != CertificateValidationStatus.FAILED && certificate.getValidationStatus() != CertificateValidationStatus.NOT_CHECKED) certificatesValidated++;
            }
            logger.debug("Validated {}/{} certificates", certificatesValidated, certificates.size());
        }

        if (validationMessage.getDiscoveryUuid() != null) {
            certificates = certificateRepository.findByValidationStatusAndCertificateContentDiscoveryCertificatesDiscoveryUuid(CertificateValidationStatus.NOT_CHECKED, validationMessage.getDiscoveryUuid());

            logger.debug("Validating {} certificates from discovery {}", certificates.size(), validationMessage.getDiscoveryName());
            for (Certificate certificate : certificates) {
                certificateHandler.validate(certificate);
            }
            logger.debug("Certificates from discovery {} validated", validationMessage.getDiscoveryName());
        }

        if (validationMessage.getLocationUuid() != null) {
            certificates = certificateRepository.findByValidationStatusAndLocationsLocationUuid(CertificateValidationStatus.NOT_CHECKED, validationMessage.getLocationUuid());

            logger.debug("Validating {} certificates from location {}", certificates.size(), validationMessage.getLocationName());
            for (Certificate certificate : certificates) {
                certificateHandler.validate(certificate);
            }
            logger.debug("Certificates from location {} validated", validationMessage.getLocationName());
        }
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCertificateHandler(CertificateHandler certificateHandler) {
        this.certificateHandler = certificateHandler;
    }
}
