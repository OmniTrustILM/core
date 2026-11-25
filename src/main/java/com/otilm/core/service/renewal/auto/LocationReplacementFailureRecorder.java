package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.TriggerInternalService;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Records that a renewed certificate could not replace the old one in its locations, or be pushed to the location that
 * renewed it, when an automatic renewal started it. The renewal itself succeeded, so the failure counts no attempt and
 * nothing is retried: it is written, with the locations each certificate is in by then, to the old certificate's
 * history and to the history of the trigger firing that started the renewal.
 */
@Component
public class LocationReplacementFailureRecorder {

    private static final Logger logger = LoggerFactory.getLogger(LocationReplacementFailureRecorder.class);

    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateRenewalLocationRepository renewalLocationRepository;
    private final CertificateLocationRepository certificateLocationRepository;
    private final LocationRepository locationRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;
    private final TriggerInternalService triggerService;
    private final TransactionTemplate newTransaction;

    public LocationReplacementFailureRecorder(CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateRenewalLocationRepository renewalLocationRepository,
            CertificateLocationRepository certificateLocationRepository, LocationRepository locationRepository,
            CertificateEventHistoryInternalService eventHistoryService, @Lazy TriggerInternalService triggerService,
            PlatformTransactionManager transactionManager) {
        this.renewalInfoRepository = renewalInfoRepository;
        this.renewalLocationRepository = renewalLocationRepository;
        this.certificateLocationRepository = certificateLocationRepository;
        this.locationRepository = locationRepository;
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
        writeFailure(predecessorUuid, successorUuid,
                () -> renewalInfoRepository
                        .findByCertificateUuid(predecessorUuid)
                        .filter(row -> successorUuid.equals(row.getRenewSuccessorUuid()))
                        .map(row -> new Failure("replacing the old certificate in its locations failed",
                                row.getRenewTriggerHistoryUuid(), row.getRenewExecutionUuid())),
                reason);
    }

    /**
     * Records that the successor a location renewed {@code predecessorUuid} with could not be pushed to that location,
     * when that location's automatic renewal tracks it, and does nothing otherwise. Never throws.
     *
     * @param reason why the push failed, as shaped for the history
     */
    public void recordLocationFailure(UUID predecessorUuid, UUID successorUuid, UUID locationUuid, String reason) {
        writeFailure(predecessorUuid, successorUuid,
                () -> renewalLocationRepository
                        .findByCertificateUuidAndLocationUuid(predecessorUuid, locationUuid)
                        .filter(row -> successorUuid.equals(row.getSuccessorUuid()))
                        .map(row -> new Failure(
                                "pushing it to location %s failed".formatted(locationName(locationUuid)),
                                row.getTriggerHistoryUuid(), row.getExecutionUuid())),
                reason);
    }

    private void writeFailure(UUID predecessorUuid, UUID successorUuid, Supplier<Optional<Failure>> trackedFailure,
            String reason) {
        RecordedFailure recorded;
        try {
            Optional<RecordedFailure> written = newTransaction
                    .execute(status -> trackedFailure
                            .get()
                            .map(failure -> recordHistory(predecessorUuid, successorUuid, failure, reason)));
            if (written.isEmpty()) {
                return;
            }
            recorded = written.get();
        } catch (RuntimeException e) {
            logger
                    .error("Could not record that certificate {} did not replace certificate {} in its locations",
                            successorUuid, predecessorUuid, e);
            return;
        }
        logger
                .info("Automatic renewal of certificate {}: certificate {} did not replace it in its locations",
                        predecessorUuid, successorUuid);
        if (recorded.triggerHistoryUuid() == null) {
            return;
        }
        try {
            newTransaction.executeWithoutResult(status -> {
                triggerService
                        .createTriggerHistoryRecord(recorded.triggerHistoryUuid(), null, recorded.executionUuid(),
                                recorded.message());
                triggerService.setTriggerHistoryActionsPerformedFalse(recorded.triggerHistoryUuid());
            });
        } catch (RuntimeException e) {
            logger
                    .warn("Could not add the failed replacement of certificate {} by certificate {} to trigger history {}",
                            predecessorUuid, successorUuid, recorded.triggerHistoryUuid());
            logger.debug("Trigger history record failed", e);
        }
    }

    private RecordedFailure recordHistory(UUID predecessorUuid, UUID successorUuid, Failure failure, String reason) {
        String message = ("The renewed certificate %s was issued, but %s and is not retried: %s. The renewed"
                + " certificate is in %s; the old certificate is still in %s")
                .formatted(successorUuid, failure.what(), reason, locationsOf(successorUuid),
                        locationsOf(predecessorUuid));
        eventHistoryService
                .addEventHistory(predecessorUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, "");
        return new RecordedFailure(message, failure.triggerHistoryUuid(), failure.executionUuid());
    }

    /** What failed, and the firing that started the renewal, either of which may be null. */
    private record Failure(String what, UUID triggerHistoryUuid, UUID executionUuid) {
    }

    private record RecordedFailure(String message, UUID triggerHistoryUuid, UUID executionUuid) {
    }

    private String locationName(UUID locationUuid) {
        return locationRepository.findByUuid(locationUuid).map(Location::getName).orElse(locationUuid.toString());
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
