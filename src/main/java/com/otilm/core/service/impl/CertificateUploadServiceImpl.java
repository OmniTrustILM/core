package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.EventException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry.DetectedCertificate;
import com.otilm.core.certificate.type.ParsedCertificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.handlers.CertificateUploadedEventHandler;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CertificateUploadServiceImpl implements CertificateUploadService {

    private CertificateRepository certificateRepository;
    private AttributeEngine attributeEngine;
    private CertificateUploadedEventHandler certificateUploadedEventHandler;
    private EventProducer eventProducer;
    private CertificateTypeHandlerRegistry certificateTypeHandlerRegistry;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCertificateUploadedEventHandler(CertificateUploadedEventHandler certificateUploadedEventHandler) {
        this.certificateUploadedEventHandler = certificateUploadedEventHandler;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setCertificateTypeHandlerRegistry(CertificateTypeHandlerRegistry certificateTypeHandlerRegistry) {
        this.certificateTypeHandlerRegistry = certificateTypeHandlerRegistry;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public String upload(String certificateData, List<RequestAttribute> customAttributes, boolean sync)
            throws AlreadyExistException, CertificateException {
        String fingerprint = parseUploadedCertificate(certificateData).properties().fingerprint();
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            throw new AlreadyExistException("Certificate already exists with fingerprint " + fingerprint);
        }

        if (customAttributes != null && !customAttributes.isEmpty()) {
            attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, customAttributes);
        }

        CertificateUploadEventMessageData eventMessageData = CertificateUploadEventMessageData
                .builder()
                .customAttributes(customAttributes)
                .certificateContent(certificateData)
                .build();
        EventMessage eventMessage = CertificateUploadedEventHandler.constructEventMessage(eventMessageData);
        if (sync) {
            try {
                certificateUploadedEventHandler.handleEvent(eventMessage);
            } catch (EventException e) {
                throw new CertificateException("Failed to produce certificate upload event: " + e.getMessage());
            }
            if (certificateRepository.findByFingerprint(fingerprint).isEmpty()) {
                throw new CertificateException(
                        "Certificate was not uploaded. See Certificate Uploaded Event History for more details.");
            }
        } else {
            eventProducer.produceMessage(eventMessage);
        }
        return fingerprint;
    }

    // Content no handler recognises is passed to the legacy parser for the specific refusal it gives, such as for a
    // keystore.
    private ParsedCertificate parseUploadedCertificate(String certificateData) {
        byte[] content = Base64.getDecoder().decode(certificateData);
        return certificateTypeHandlerRegistry
                .detectCertificate(content)
                .map(DetectedCertificate::certificate)
                .orElseGet(() -> {
                    CertificateUtil.parseUploadedCertificateContent(certificateData);
                    throw new ValidationException("Uploaded certificate content has invalid or unsupported format.");
                });
    }
}
