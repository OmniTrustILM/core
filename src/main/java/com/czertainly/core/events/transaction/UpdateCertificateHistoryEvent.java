package com.czertainly.core.events.transaction;

import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.czertainly.core.service.CertificateEventHistoryInternalService;

import java.util.UUID;

/**
 * Records a certificate history entry. Publish this only for records describing committed work — a rollback of the publishing
 * transaction discards the event, so the history record dies together with the work it describes.
 *
 * <p>Do NOT publish this for FAILED records on a code path whose transaction is about to roll back: the event would be
 * silently dropped and the failure would leave no trace. Use {@link CertificateEventHistoryInternalService#addEventHistorySurvivingRollback}
 * instead, which commits independently of the caller's transaction.</p>
 */
public record UpdateCertificateHistoryEvent(UUID certificateUuid, CertificateEvent certificateEvent, CertificateEventStatus eventStatus, String message, String detail) {

    public UpdateCertificateHistoryEvent(UUID certificateUuid, CertificateEvent certificateEvent, CertificateEventStatus eventStatus, IPlatformEnum oldStatus, IPlatformEnum newStatus) {
        this(certificateUuid, certificateEvent, eventStatus, "Certificate %s changed from %s to %s.".formatted(certificateEvent == CertificateEvent.UPDATE_STATE ? "state" : "validation status", oldStatus.getLabel(), newStatus.getLabel()), null);
    }
}
