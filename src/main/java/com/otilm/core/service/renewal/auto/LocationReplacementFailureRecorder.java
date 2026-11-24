package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.TriggerInternalService;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Records that a renewed certificate could not replace the old one in its locations, when an automatic renewal started
 * it. The renewal itself succeeded, so the failure counts no attempt and nothing is retried: it is written, with the
 * locations each certificate is in by then, to the old certificate's history and to the history of the trigger firing
 * that started the renewal.
 */
@Component
public class LocationReplacementFailureRecorder {

    private static final Logger logger = LoggerFactory.getLogger(LocationReplacementFailureRecorder.class);

    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateLocationRepository certificateLocationRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;
    private final TriggerInternalService triggerService;
    private final TransactionTemplate newTransaction;

    public LocationReplacementFailureRecorder(CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateLocationRepository certificateLocationRepository,
            CertificateEventHistoryInternalService eventHistoryService, @Lazy TriggerInternalService triggerService,
            PlatformTransactionManager transactionManager) {
        this.renewalInfoRepository = renewalInfoRepository;
        this.certificateLocationRepository = certificateLocationRepository;
        this.eventHistoryService = eventHistoryService;
        this.triggerService = triggerService;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Records the failure when {@code successorUuid} is the automatic renewal of {@code predecessorUuid}, and does
     * nothing otherwise. Never throws: the caller reports the failure itself.
     *
     * @param reason why the replacement failed, as shaped for the history
     */
    public void recordFailure(UUID predecessorUuid, UUID successorUuid, String reason) {
        String message;
        UUID triggerHistoryUuid;
        UUID executionUuid;
        try {
            Optional<RenewalInfoSnapshot> recorded = Optional
                    .ofNullable(
                            newTransaction.execute(status -> recordHistory(predecessorUuid, successorUuid, reason)));
            if (recorded.isEmpty()) {
                return;
            }
            RenewalInfoSnapshot snapshot = recorded.get();
            message = snapshot.message();
            triggerHistoryUuid = snapshot.triggerHistoryUuid();
            executionUuid = snapshot.executionUuid();
        } catch (RuntimeException e) {
            logger
                    .error("Could not record that certificate {} did not replace certificate {} in its locations",
                            successorUuid, predecessorUuid, e);
            return;
        }
        logger
                .info("Automatic renewal of certificate {}: certificate {} did not replace it in its locations",
                        predecessorUuid, successorUuid);
        if (triggerHistoryUuid == null) {
            return;
        }
        try {
            newTransaction.executeWithoutResult(status -> {
                triggerService.createTriggerHistoryRecord(triggerHistoryUuid, null, executionUuid, message);
                triggerService.setTriggerHistoryActionsPerformedFalse(triggerHistoryUuid);
            });
        } catch (RuntimeException e) {
            logger
                    .warn("Could not add the failed replacement of certificate {} by certificate {} to trigger history {}",
                            predecessorUuid, successorUuid, triggerHistoryUuid);
            logger.debug("Trigger history record failed", e);
        }
    }

    private RenewalInfoSnapshot recordHistory(UUID predecessorUuid, UUID successorUuid, String reason) {
        CertificateRenewalInfo row = renewalInfoRepository.findByCertificateUuid(predecessorUuid).orElse(null);
        if (row == null || !successorUuid.equals(row.getRenewSuccessorUuid())) {
            return null;
        }
        String message = ("The renewed certificate %s was issued, but replacing the old certificate in its locations"
                + " failed and is not retried: %s. The renewed certificate is in %s; the old certificate is still in %s")
                .formatted(successorUuid, reason, locationsOf(successorUuid), locationsOf(predecessorUuid));
        eventHistoryService
                .addEventHistory(predecessorUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, "");
        return new RenewalInfoSnapshot(message, row.getRenewTriggerHistoryUuid(), row.getRenewExecutionUuid());
    }

    private record RenewalInfoSnapshot(String message, UUID triggerHistoryUuid, UUID executionUuid) {
    }

    private String locationsOf(UUID certificateUuid) {
        String names = certificateLocationRepository
                .findByCertificateUuid(certificateUuid)
                .stream()
                .map(entry -> entry.getLocation().getName())
                .sorted()
                .collect(Collectors.joining(", "));
        return names.isEmpty() ? "no location" : names;
    }
}
