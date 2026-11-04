package com.otilm.core.service.handler;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.events.transaction.UploaderOwnershipEvent;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Makes the uploader the owner of an uploaded certificate in a transaction of its own, after the upload has committed.
 * Ownership is an extra: a failure is logged and leaves the certificate as uploaded, without an owner. A certificate
 * that has an owner by then, such as one an upload trigger set, keeps it.
 *
 * <p>
 * It runs ahead of the other after-commit listeners, so a notification an upload trigger sends to the owner finds the
 * owner stored when the message is consumed.
 * </p>
 */
@Component
public class UploaderOwnershipListener {

    private static final Logger logger = LoggerFactory.getLogger(UploaderOwnershipListener.class);

    private final ResourceObjectAssociationService objectAssociationService;
    private final CertificateEventHistoryInternalService certificateEventHistoryService;
    private final TransactionHandler transactionHandler;

    public UploaderOwnershipListener(ResourceObjectAssociationService objectAssociationService,
            CertificateEventHistoryInternalService certificateEventHistoryService,
            TransactionHandler transactionHandler) {
        this.objectAssociationService = objectAssociationService;
        this.certificateEventHistoryService = certificateEventHistoryService;
        this.transactionHandler = transactionHandler;
    }

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleUploaderOwnership(UploaderOwnershipEvent event) {
        try {
            transactionHandler.runInNewTransaction(() -> {
                assignUnlessOwned(event);
            });
        } catch (RuntimeException e) {
            logger
                    .warn("Unable to make {} owner of uploaded certificate {}. The certificate has no owner. Message: {}",
                            event.uploaderName(), event.certificateUuid(), e.getMessage());
        }
    }

    private void assignUnlessOwned(UploaderOwnershipEvent event) {
        if (objectAssociationService.getOwner(Resource.CERTIFICATE, event.certificateUuid()) != null) {
            return;
        }
        objectAssociationService
                .setOwner(Resource.CERTIFICATE, event.certificateUuid(), event.uploaderUuid(), event.uploaderName());
        certificateEventHistoryService
                .addEventHistory(event.certificateUuid(), CertificateEvent.UPDATE_OWNER, CertificateEventStatus.SUCCESS,
                        "%s -> %s"
                                .formatted(CertificateEventHistoryInternalService.UNDEFINED_OBJECT_NAME,
                                        event.uploaderName()),
                        "");
    }
}
