package com.otilm.core.events.handlers;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.EventException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.events.data.CertificateEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.CertificateUploadSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventHandler;
import com.otilm.core.events.data.EventDataBuilder;
import com.otilm.core.events.transaction.CertificateValidationEvent;
import com.otilm.core.events.transaction.UploaderOwnershipEvent;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.X509ObjectToString;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component(ResourceEvent.Codes.CERTIFICATE_UPLOADED)
public class CertificateUploadedEventHandler extends EventHandler<Certificate> {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUploadedEventHandler.class);

    private final CertificateRepository certificateRepository;
    private CertificateInternalService certificateService;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private AttributeEngine attributeEngine;
    private TriggerHistoryRepository triggerHistoryRepository;

    @Autowired
    public void setTriggerHistoryRepository(TriggerHistoryRepository triggerHistoryRepository) {
        this.triggerHistoryRepository = triggerHistoryRepository;
    }

    @Autowired
    public void setCertificateEventHistoryService(
            CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    protected CertificateUploadedEventHandler(CertificateRepository repository,
            TriggerEvaluator<Certificate> triggerEvaluator) {
        super(repository, triggerEvaluator);
        this.certificateRepository = repository;
    }

    /**
     * Resolved on the producing thread — the consuming JMS listener thread has no SecurityContext, so the message is
     * the only channel carrying the uploader to the audited writes.
     * <p>
     * This also widens authorization: the listener authenticates for the whole {@link #handleEvent} call, so trigger
     * evaluation and the attribute engine's permission filters run as the uploader rather than unauthenticated. Nothing
     * here is {@code @ExternalAuthorization}-gated, so an upload cannot newly be denied, and trigger actions still use
     * the association owner's permissions via {@code handleUser}.
     */
    public static EventMessage constructEventMessage(CertificateUploadEventMessageData data) {
        return new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null, null, null, data,
                AuthHelper.getActingUserUuidOrNull(), null);
    }

    @Override
    protected Object getEventData(Certificate object, Object eventMessageData) {
        return EventDataBuilder.getCertificateUploadedEventData(object);
    }

    @Override
    protected EventContext<Certificate> prepareContext(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = new EventContext<>(eventMessage, triggerEvaluator,
                new X509CertificateEntity(), null);
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones
        return context;
    }

    @Override
    @Transactional
    public void handleEvent(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = prepareContext(eventMessage);
        EventHistory eventHistory = createEventHistory(ResourceEvent.CERTIFICATE_UPLOADED, null, null);
        CertificateUploadEventMessageData eventMessageData = objectMapper
                .convertValue(eventMessage.getData(), CertificateUploadEventMessageData.class);

        X509Certificate x509Certificate;
        try {
            x509Certificate = CertificateUtil.parseCertificate(eventMessageData.certificateContent());
        } catch (CertificateException e) {
            logger
                    .error("Unable to parse certificate {} from uploaded certificate: {}",
                            eventMessageData.certificateContent(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        String fingerprint;
        try {
            fingerprint = CertificateUtil.getThumbprint(x509Certificate);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            logger
                    .error("Unable to calculate fingerprint for certificate {}: {}",
                            eventMessageData.certificateContent(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        if (certificateRepository.findByFingerprint(fingerprint).isPresent()) {
            logger.warn("Certificate with fingerprint {} already exists, skipping upload event", fingerprint);
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }
        X509CertificateEntity certificate = X509CertificateEntity.from(context.getResourceObjects().getFirst());
        CertificateUtil.prepareIssuedCertificate(certificate, x509Certificate);
        certificate.setFingerprint(fingerprint);
        CertificateEventData eventData = (CertificateEventData) getEventData(certificate, eventMessageData);
        // Always a non-null list, even if the request omitted custom attributes entirely: a real Java null passed down
        // to the
        // evaluator means "this caller doesn't support pending-attribute evaluation", which would wrongly make CUSTOM
        // EMPTY
        // conditions fail to match on an unpersisted certificate (no UUID) instead of correctly evaluating to true.
        List<RequestAttribute> pendingCustomAttributes = Objects
                .requireNonNullElse(eventMessageData.customAttributes(), List.of());
        try {
            if (evaluateIgnoreTriggers(context, context.getPlatformTriggers(), certificate, eventData, eventHistory,
                    pendingCustomAttributes)) {
                saveEventHistory(eventHistory, EventStatus.FINISHED);
                return;
            }
            saveCertificate(certificate, fingerprint, x509Certificate);
            eventData.setCertificateUuid(certificate.getUuid());
            // Retroactively link trigger histories of the ignore triggers to the certificate
            triggerHistoryRepository
                    .updateObjectUuidAndObjectResource(certificate.getUuid(), Resource.CERTIFICATE,
                            eventHistory.getUuid());

            evaluateTriggers(context, context.getPlatformTriggers(), certificate, eventData, eventHistory,
                    pendingCustomAttributes);
        } catch (Exception e) {
            logger
                    .error("Unable to process triggers for {} object {}. Message: {}", context.getResource().getLabel(),
                            certificate.toStringShort(), e.getMessage());
            saveEventHistory(eventHistory, EventStatus.FAILED);
            return;
        }

        assignUploaderAsOwnerIfEnabled(certificate.getUuid(), eventHistory);

        saveEventHistory(eventHistory, EventStatus.FINISHED);

        if (eventMessageData.customAttributes() != null && !eventMessageData.customAttributes().isEmpty()) {
            try {
                attributeEngine
                        .updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificate.getUuid(),
                                eventMessageData.customAttributes());
            } catch (NotFoundException | AttributeException e) {
                logger
                        .error("Error updating custom attributes for certificate {}: {}", certificate.getUuid(),
                                e.getMessage());
            }
        }

        certificateEventHistoryService
                .addEventHistory(certificate.getUuid(), CertificateEvent.UPLOAD, CertificateEventStatus.SUCCESS,
                        "Certificate uploaded", "");
        applicationEventPublisher.publishEvent(new CertificateValidationEvent(certificate.getUuid()));
        sendFollowUpEventsNotifications(context);
    }

    private void assignUploaderAsOwnerIfEnabled(UUID certificateUuid, EventHistory eventHistory) {
        PlatformSettingsDto platformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        CertificateSettingsDto certificates = platformSettings == null ? null : platformSettings.getCertificates();
        CertificateUploadSettingsDto upload = certificates == null ? null : certificates.getUpload();
        if (upload == null || !upload.isAutomaticOwnership()) {
            return;
        }
        if (triggerSetsOwner(eventHistory)) {
            return;
        }
        NameAndUuidDto uploader = AuthHelper.getActingUserOrNull();
        if (uploader == null) {
            logger
                    .warn("Automatic ownership is on, but the uploader of certificate {} is not known. The certificate "
                            + "has no owner.", certificateUuid);
            return;
        }
        applicationEventPublisher
                .publishEvent(new UploaderOwnershipEvent(certificateUuid, UUID.fromString(uploader.getUuid()),
                        uploader.getName()));
    }

    /**
     * Whether an upload trigger that applies to the certificate sets its owner, whether to a user or to nobody. Such a
     * trigger decides the owner, so automatic ownership leaves the certificate as the trigger left it.
     */
    private boolean triggerSetsOwner(EventHistory eventHistory) {
        return triggerHistoryRepository
                .existsMatchedSetFieldExecution(eventHistory.getUuid(), ExecutionType.SET_FIELD,
                        FilterFieldSource.PROPERTY, FilterField.OWNER.name());
    }

    private void saveCertificate(Certificate certificate, String fingerprint, X509Certificate x509Certificate) {
        CertificateContent certificateContent = certificateService
                .checkAddCertificateContent(fingerprint, X509ObjectToString.toPem(x509Certificate));
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
        NotificationMessage notificationMessage = new NotificationMessage(eventContext.getEvent(), Resource.CERTIFICATE,
                certificate.getUuid(), null,
                NotificationRecipient.buildUserNotificationRecipient(certificate.getUserUuid()), eventData);
        applicationEventPublisher.publishEvent(notificationMessage);
    }
}
