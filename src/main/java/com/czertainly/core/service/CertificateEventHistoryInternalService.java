package com.czertainly.core.service;

import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateEventStatus;

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
     *
     * @param certificateUuid UUID of certificate that should record the event
     * @param event Certificate event
     * @param status Event result
     * @param message Short message for the event
     * @param additionalInformation Additional information
     */
    void addEventHistorySurvivingRollback(UUID certificateUuid, CertificateEvent event, CertificateEventStatus status, String message, String additionalInformation);

}
