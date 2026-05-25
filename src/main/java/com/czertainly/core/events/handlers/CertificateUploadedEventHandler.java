package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.EventException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.events.data.CertificateEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.api.model.core.workflows.EventStatus;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.workflows.EventHistory;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.workflows.TriggerHistoryRepository;
import com.czertainly.core.evaluator.TriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.EventHandler;
import com.czertainly.core.events.data.EventDataBuilder;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.messaging.model.CertificateUploadEventMessageData;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.messaging.model.NotificationRecipient;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.X509ObjectToString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Component(ResourceEvent.Codes.CERTIFICATE_UPLOADED)
public class CertificateUploadedEventHandler extends EventHandler<Certificate> {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUploadedEventHandler.class);

    private final CertificateRepository certificateRepository;
    private CertificateService certificateService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private AttributeEngine attributeEngine;
    private TriggerHistoryRepository triggerHistoryRepository;


    @Autowired
    public void setTriggerHistoryRepository(TriggerHistoryRepository triggerHistoryRepository) {
        this.triggerHistoryRepository = triggerHistoryRepository;
    }

    @Autowired
    public void setCertificateEventHistoryService(CertificateEventHistoryService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }


    protected CertificateUploadedEventHandler(CertificateRepository repository, TriggerEvaluator<Certificate> triggerEvaluator) {
        super(repository, triggerEvaluator);
        this.certificateRepository = repository;
    }

    public static EventMessage constructEventMessage(CertificateUploadEventMessageData data) {
        return new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null, data);
    }

    @Override
    protected Object getEventData(Certificate object, Object eventMessageData) {
        return EventDataBuilder.getCertificateUploadedEventData(object);
    }

    @Override
    protected EventContext<Certificate> prepareContext(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = new EventContext<>(eventMessage, triggerEvaluator, new Certificate(), null);
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones
        return context;
    }

    @Override
    @Transactional
    public void handleEvent(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = prepareContext(eventMessage);
        EventHistory eventHistory = createEventHistory(ResourceEvent.CERTIFICATE_UPLOADED, null, null);
        CertificateUploadEventMessageData eventMessageData = objectMapper.convertValue(eventMessage.getData(), CertificateUploadEventMessageData.class);

        X509Certificate x509Certificate;
        try {
            x509Certificate = CertificateUtil.parseCertificate(eventMessageData.certificateContent());
        } catch (CertificateException e) {
            logger.error("Unable to parse certificate {} from uploaded certificate: {}", eventMessageData.certificateContent(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        String fingerprint;
        try {
            fingerprint = CertificateUtil.getThumbprint(x509Certificate);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            logger.error("Unable to calculate fingerprint for certificate {}: {}", eventMessageData.certificateContent(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            logger.warn("Certificate with fingerprint {} already exists, skipping upload event", fingerprint);
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        Certificate certificate = context.getResourceObjects().getFirst();
        CertificateUtil.prepareIssuedCertificate(certificate, x509Certificate);
        certificate.setFingerprint(fingerprint);
        CertificateEventData eventData = (CertificateEventData) getEventData(certificate, eventMessageData);
        try {
            if (evaluateIgnoreTriggers(context, context.getPlatformTriggers(), certificate, eventData, eventHistory)) {
                saveEventHistory(eventHistory, EventStatus.FINISHED);
                return;
            }
            saveCertificate(certificate, fingerprint, x509Certificate);
            eventData.setCertificateUuid(certificate.getUuid());
            // Retroactively link trigger histories of the ignore triggers to the certificate
            triggerHistoryRepository.updateObjectUuidAndObjectResource(certificate.getUuid(), Resource.CERTIFICATE, eventHistory.getUuid());

            evaluateTriggers(context, context.getPlatformTriggers(), certificate, eventData, eventHistory);
        } catch (Exception e) {
            logger.error("Unable to process triggers for {} object {}. Message: {}", context.getResource().getLabel(), certificate.toStringShort(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }

        saveEventHistory(eventHistory, EventStatus.FINISHED);

        if (eventMessageData.customAttributes() != null && !eventMessageData.customAttributes().isEmpty()) {
            try {
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), eventMessageData.customAttributes());
            } catch (NotFoundException | AttributeException e) {
                logger.error("Error updating custom attributes for certificate {}: {}", certificate.getUuid(), e.getMessage());
            }
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");
        applicationEventPublisher.publishEvent(new CertificateValidationEvent(certificate.getUuid()));
        sendFollowUpEventsNotifications(context);
    }

    private void saveCertificate(Certificate certificate, String fingerprint, X509Certificate x509Certificate) {
        CertificateContent certificateContent = certificateService.checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Certificate));
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());

        byte[] altPublicKey = x509Certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        certificateService.uploadCertificateKey(x509Certificate.getPublicKey(), certificate, altPublicKey);
        repository.save(certificate);
    }

    @Override
    protected void sendFollowUpEventsNotifications(EventContext<Certificate> eventContext) {
        final Certificate certificate = eventContext.getResourceObjects().getFirst();
        final Object eventData = getEventData(certificate, eventContext.getData());
        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.CERTIFICATE, certificate.getUuid(), null, NotificationRecipient.buildUserNotificationRecipient(certificate.getUserUuid()), eventData);
        notificationProducer.produceMessage(notificationMessage);
    }
}
