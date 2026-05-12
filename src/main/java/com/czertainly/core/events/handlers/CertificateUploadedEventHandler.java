package com.czertainly.core.events.handlers;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.EventException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.events.data.CertificateUploadedEventData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.evaluator.TriggerEvaluator;
import com.czertainly.core.events.EventContext;
import com.czertainly.core.events.EventHandler;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.messaging.model.EventMessage;
import com.czertainly.core.service.CertificateEventHistoryService;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.X509ObjectToString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateUploadedEventHandler extends EventHandler<Certificate> {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUploadedEventHandler.class);

    private CertificateService certificateService;
    private CertificateEventHistoryService certificateEventHistoryService;
    private AttributeEngine attributeEngine;


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
    }

    public static EventMessage constructEventMessage(CertificateUploadedEventData data) {
        return new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null, data);
    }

    @Override
    protected Object getEventData(Certificate object, Object eventMessageData) {
        return objectMapper.convertValue(eventMessageData, CertificateUploadedEventData.class);
    }

    @Override
    protected EventContext<Certificate> prepareContext(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = new EventContext<>(eventMessage, triggerEvaluator, null, null);
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones

        return context;
    }

    @Override
    public void handleEvent(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = prepareContext(eventMessage);
        // TODO: add event history
        CertificateUploadedEventData data = (CertificateUploadedEventData) context.getData();
        Certificate certificate = new Certificate();
        CertificateUtil.prepareIssuedCertificate(certificate, data.getCertificate());

        if (evaluateIgnoreTriggers(context, context.getPlatformTriggers(), certificate, context.getData())) {
            return;
        }

        saveCertificate(data, certificate);
        evaluateTriggers(context, context.getPlatformTriggers(), certificate, context.getData());

        if (data.getCustomAttributes() != null && !data.getCustomAttributes().isEmpty()) {
            try {
                attributeEngine.updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(), data.getCustomAttributes());
            } catch (NotFoundException | AttributeException e) {
                logger.error("Error updating custom attributes for certificate {}: {}", certificate.getUuid(), e.getMessage());
            }
        }

        if (data.getUserUuid() != null) {
            try {
                certificateService.updateCertificateUser(certificate.getUuid(), String.valueOf(data.getUserUuid()));
            } catch (NotFoundException e) {
                logger.error("Error updating user for certificate {}: {}", certificate.getUuid(), e.getMessage());
            }
        }

        certificateEventHistoryService.addEventHistory(certificate.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS, "Certificate uploaded", "");
        applicationEventPublisher.publishEvent(new CertificateValidationEvent(certificate.getUuid()));
    }

    private void saveCertificate(CertificateUploadedEventData data, Certificate certificate) {
        CertificateContent certificateContent = certificateService.checkAddCertificateContent(data.getFingerprint(), X509ObjectToString.toPem(data.getCertificate()));
        certificate.setFingerprint(data.getFingerprint());
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());

        byte[] altPublicKey = data.getCertificate().getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        certificateService.uploadCertificateKey(data.getCertificate().getPublicKey(), certificate, altPublicKey);
        repository.save(certificate);
    }


}
