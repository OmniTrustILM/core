package com.czertainly.core.service;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;

import java.util.HashMap;
import java.util.UUID;

public interface CertificateEventHistoryInternalService {

    /**
     * Method to add event into the Certificate history.
     * @param certificateUuid UUID of certificate that should record the event
     * @param event Certificate event
     * @param status Event result
     * @param message Short message for the event
     * @param additionalInformation Additional information as key-value pairs
     */
    void addEventHistory(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, HashMap<String, Object> additionalInformation);

    void addEventHistory(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, String additionalInformation);

    /**
     * Records the event in the Certificate history in a separate transaction that commits independently of the caller's transaction.
     * Use for FAILED events recorded on a code path whose surrounding transaction is about to roll back — a regular {@code addEventHistory}
     * call (or an {@code AFTER_COMMIT} transactional event) would be discarded with the rollback.
     * <p>
     * <strong>Call this before the surrounding transaction UPDATEs or locks the certificate row.</strong> Because this runs in a
     * separate ({@code REQUIRES_NEW}) transaction, its FK insert against the certificate would block on a row lock the suspended
     * caller still holds — a single-thread self-deadlock.</p>
     *
     * @param certificateUuid UUID of certificate that should record the event
     * @param event Certificate event
     * @param status Event result
     * @param message Short message for the event
     * @param additionalInformation Additional information
     */
    void addEventHistorySurvivingRollback(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, String additionalInformation);

}
