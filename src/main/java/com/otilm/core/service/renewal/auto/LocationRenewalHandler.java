package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateLocationId;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.LocationExternalService;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.FailureCount;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.SuccessorStatus;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitGuardResult;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitInput;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitOutcome;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Renews a certificate in each location that generates its own key and request. Each location is its own unit of work,
 * so one location's failure leaves the others in place. Push-only locations are not updated; they are named once in the
 * certificate history.
 */
@Component
public class LocationRenewalHandler implements AutoRenewalHandler {

    private static final Logger logger = LoggerFactory.getLogger(LocationRenewalHandler.class);

    private final LocationExternalService locationService;
    private final CertificateRenewalLocationRepository renewalLocationRepository;
    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateLocationRepository certificateLocationRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;
    private final EntityManager entityManager;
    private final TransactionTemplate newTransaction;
    private final TransactionTemplate readOnlyTransaction;

    /** The location service reaches the trigger evaluator through the certificate service, so it is injected lazily. */
    public LocationRenewalHandler(@Lazy LocationExternalService locationService,
            CertificateRenewalLocationRepository renewalLocationRepository,
            CertificateRenewalInfoRepository renewalInfoRepository, CertificateRepository certificateRepository,
            CertificateLocationRepository certificateLocationRepository,
            CertificateEventHistoryInternalService eventHistoryService, EntityManager entityManager,
            PlatformTransactionManager transactionManager) {
        this.locationService = locationService;
        this.renewalLocationRepository = renewalLocationRepository;
        this.renewalInfoRepository = renewalInfoRepository;
        this.certificateRepository = certificateRepository;
        this.certificateLocationRepository = certificateLocationRepository;
        this.eventHistoryService = eventHistoryService;
        this.entityManager = entityManager;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.readOnlyTransaction = new TransactionTemplate(transactionManager);
        this.readOnlyTransaction.setReadOnly(true);
    }

    @Override
    public AutoRenewalMode mode() {
        return AutoRenewalMode.LOCATION;
    }

    @Override
    public void renew(Certificate certificate, RenewalContext context) throws AutoRenewalException {
        UUID certificateUuid = certificate.getUuid();
        List<Target> targets = new ArrayList<>();
        List<String> pushOnly = new ArrayList<>();
        readOnlyTransaction.executeWithoutResult(status -> readLocations(certificateUuid, targets, pushOnly));
        inNewTransaction(() -> trackLocations(certificateUuid, targets, pushOnly));
        inNewTransaction(() -> settleDetached(certificateUuid, targets, context.now()));

        List<String> failures = new ArrayList<>();
        for (Target target : targets) {
            renewIn(certificateUuid, target, context).ifPresent(failures::add);
        }
        if (!failures.isEmpty()) {
            throw new AutoRenewalException(String.join("; ", failures));
        }
    }

    /** Splits the locations holding the certificate into the key-generating targets and the push-only names. */
    private void readLocations(UUID certificateUuid, List<Target> targets, List<String> pushOnly) {
        Certificate certificate = certificateRepository
                .findById(certificateUuid)
                .orElseThrow(
                        () -> new IllegalStateException("Certificate %s no longer exists".formatted(certificateUuid)));
        for (CertificateLocation entry : certificate.getLocations()) {
            Location location = entry.getLocation();
            if (AutoRenewalModeResolver.isKeyGenerating(entry)) {
                targets
                        .add(new Target(location.getUuid(), location.getEntityInstanceReferenceUuid(),
                                location.getName()));
            } else if (location != null) {
                pushOnly.add(location.getName());
            }
        }
        targets.sort(Comparator.comparing(Target::name, Comparator.nullsFirst(Comparator.naturalOrder())));
    }

    /** Renews in one location when its guards allow; answers the failure to record, if any. */
    private Optional<String> renewIn(UUID certificateUuid, Target target, RenewalContext context) {
        LocationClaim claim = inNewTransaction(() -> claim(certificateUuid, target, context));
        if (claim.reopened()) {
            inNewTransaction(() -> clearRenewAt(certificateUuid));
        }
        if (claim.failure() != null) {
            return Optional.of(claim.failure());
        }
        if (!claim.start()) {
            return Optional.empty();
        }
        try {
            UUID successorUuid = renewAndStoreSuccessor(certificateUuid, target);
            logger
                    .info("Automatic renewal of certificate {} in location {} requested certificate {}",
                            certificateUuid, target.locationUuid(), successorUuid);
            return Optional.empty();
        } catch (RuntimeException e) {
            String reason = describe(e, certificateUuid, target);
            return Optional.of(inNewTransaction(() -> recordCallFailure(certificateUuid, target, context, reason)));
        }
    }

    /** Creates the rows of locations seen for the first time; names the push-only locations on the first handling. */
    private Void trackLocations(UUID certificateUuid, List<Target> targets, List<String> pushOnly) {
        Set<UUID> tracked = renewalLocationRepository
                .findByCertificateUuid(certificateUuid)
                .stream()
                .map(CertificateRenewalLocation::getLocationUuid)
                .collect(Collectors.toSet());
        for (Target target : targets) {
            if (!tracked.contains(target.locationUuid())) {
                CertificateRenewalLocation row = new CertificateRenewalLocation();
                row.setCertificateUuid(certificateUuid);
                row.setLocationUuid(target.locationUuid());
                renewalLocationRepository.save(row);
            }
        }
        if (tracked.isEmpty() && !pushOnly.isEmpty()) {
            addHistory(certificateUuid, "Automatic renewal does not update the push-only locations: "
                    + pushOnly.stream().sorted().collect(Collectors.joining(", ")));
        }
        return null;
    }

    /**
     * Settles the rows of locations that no longer hold the certificate, as a location replaces it with the successor
     * it renews it with. An issued successor completes an open row and one in flight keeps it; with none, or with a
     * revoked one, the location has nothing left to renew, so the row is dropped, completed or not.
     */
    private Void settleDetached(UUID certificateUuid, List<Target> targets, Instant now) {
        Set<UUID> held = targets.stream().map(Target::locationUuid).collect(Collectors.toSet());
        for (CertificateRenewalLocation tracked : renewalLocationRepository.findByCertificateUuid(certificateUuid)) {
            boolean settled = tracked.getCompletedAt() != null
                    && successorStatus(tracked.getSuccessorUuid()) != SuccessorStatus.REVOKED;
            if (!settled && !held.contains(tracked.getLocationUuid())) {
                renewalLocationRepository
                        .findAndLockSkipLocked(certificateUuid, tracked.getLocationUuid())
                        .filter(row -> !AutoRenewalGuards.markerHeld(row.getStartedAt(), now))
                        .ifPresent(row -> settleDetached(row, now));
            }
        }
        return null;
    }

    private void settleDetached(CertificateRenewalLocation row, Instant now) {
        switch (successorStatus(row.getSuccessorUuid())) {
            case ISSUED -> {
                row.setCompletedAt(now);
                logger
                        .info("Automatic renewal of certificate {} in location {} completed", row.getCertificateUuid(),
                                row.getLocationUuid());
            }
            case NONE, FAILED, REVOKED -> {
                renewalLocationRepository.delete(row);
                logger
                        .info("Automatic renewal of certificate {} in location {} dropped: the location no longer "
                                + "holds it", row.getCertificateUuid(), row.getLocationUuid());
            }
            case IN_FLIGHT -> logger
                    .debug("Automatic renewal of certificate {} in location {} waits for its successor",
                            row.getCertificateUuid(), row.getLocationUuid());
        }
    }

    private LocationClaim claim(UUID certificateUuid, Target target, RenewalContext context) {
        Instant now = context.now();
        Optional<CertificateRenewalLocation> locked = renewalLocationRepository
                .findAndLockSkipLocked(certificateUuid, target.locationUuid());
        if (locked.isEmpty() || AutoRenewalGuards.markerHeld(locked.get().getStartedAt(), now)) {
            return LocationClaim.SKIP;
        }
        CertificateRenewalLocation row = locked.get();
        UUID successorUuid = row.getSuccessorUuid();
        UnitGuardResult result = AutoRenewalGuards
                .unit(new UnitInput(row.getCompletedAt() != null, successorStatus(successorUuid),
                        foreignRenewal(certificateUuid), row.getAttempt(), row.getNotBefore(), context.maxAttempts()),
                        now);
        if (result.outcome() == UnitOutcome.REOPEN) {
            reopen(row, target, context.maxAttempts());
            return LocationClaim.REOPEN;
        }
        if (result.failure() != null) {
            row.setSuccessorUuid(null);
            String reason = "the renewed certificate %s was rejected, failed, revoked or removed"
                    .formatted(successorUuid);
            return LocationClaim.failed(storeFailure(row, target, result.failure(), reason, context.maxAttempts()));
        }
        if (result.outcome() == UnitOutcome.MARK_COMPLETED) {
            row.setCompletedAt(now);
            reportWhenNotInLocation(row, target);
            logger
                    .info("Automatic renewal of certificate {} in location {} completed", certificateUuid,
                            target.locationUuid());
        }
        if (result.outcome() != UnitOutcome.START) {
            logger
                    .debug("Automatic renewal of certificate {} in location {} skipped: {}", certificateUuid,
                            target.locationUuid(), result.outcome());
            return LocationClaim.SKIP;
        }
        row.setStartedAt(now);
        row.setOwnerUuid(context.ownerUuid());
        row.setTriggerHistoryUuid(context.triggerHistoryUuid());
        row.setExecutionUuid(context.executionUuid());
        return LocationClaim.PROCEED;
    }

    /**
     * Reopens a completed location whose successor was revoked: clears the completion and the successor, so that the
     * location is renewed again once the certificate's renewal time, cleared after this claim commits, is reached.
     */
    private void reopen(CertificateRenewalLocation row, Target target, int maxAttempts) {
        UUID revokedUuid = row.getSuccessorUuid();
        row.setCompletedAt(null);
        row.setSuccessorUuid(null);
        FailureCount count = AutoRenewalGuards.countReopen(row.getAttempt(), maxAttempts);
        String outcome = count.attempt() >= maxAttempts
                ? "the attempt limit is reached, so it is not renewed there again"
                : "the certificate is renewed there again";
        String reason = "the renewed certificate %s was revoked; %s".formatted(revokedUuid, outcome);
        addHistory(row.getCertificateUuid(), "Automatic renewal in location %s: %s (attempt %d of %d)"
                .formatted(target.name(), reason, count.attempt(), maxAttempts));
        storeFailure(row, target, count, reason, maxAttempts);
        logger
                .info("Automatic renewal of certificate {} in location {} reopened: {}", row.getCertificateUuid(),
                        target.locationUuid(), reason);
    }

    /**
     * Clears the certificate's renewal time so that the next firing chooses a new one. It runs in a transaction of its
     * own, as the window writer locks the certificate's row before its location rows.
     */
    private Void clearRenewAt(UUID certificateUuid) {
        renewalInfoRepository.findAndLockByCertificateUuid(certificateUuid).ifPresent(info -> info.setRenewAt(null));
        return null;
    }

    private SuccessorStatus successorStatus(UUID successorUuid) {
        if (successorUuid == null) {
            return SuccessorStatus.NONE;
        }
        return SuccessorStatus
                .of(certificateRepository.findById(successorUuid).map(Certificate::getState).orElse(null));
    }

    /** Another actor renews the certificate when it has a live successor that none of its locations started. */
    private boolean foreignRenewal(UUID certificateUuid) {
        Set<UUID> started = renewalLocationRepository
                .findByCertificateUuid(certificateUuid)
                .stream()
                .map(CertificateRenewalLocation::getSuccessorUuid)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        return certificateRepository
                .findById(certificateUuid)
                .map(certificate -> AutoRenewalGuards.foreignRenewal(certificate.getSuccessorRelations(), started))
                .orElse(false);
    }

    /**
     * Renews in the location without a transaction, as the renewal calls out to connectors; the location service opens
     * only short transactions of its own around its local reads and writes. The successor is stored on the row before
     * its renewal is queued, in a transaction of its own, so it stays tracked when a later step of the location's
     * renewal fails after the request was committed.
     */
    private UUID renewAndStoreSuccessor(UUID certificateUuid, Target target) {
        Consumer<UUID> trackSuccessor = successorUuid -> inNewTransaction(() -> {
            lockRow(certificateUuid, target).setSuccessorUuid(successorUuid);
            return successorUuid;
        });
        UUID successorUuid = renewInLocation(certificateUuid, target, trackSuccessor);
        return inNewTransaction(() -> {
            CertificateRenewalLocation row = lockRow(certificateUuid, target);
            row.setSuccessorUuid(successorUuid);
            row.setStartedAt(null);
            return successorUuid;
        });
    }

    private UUID renewInLocation(UUID certificateUuid, Target target, Consumer<UUID> trackSuccessor) {
        try {
            return locationService
                    .renewCertificateInLocationForSuccessor(SecuredParentUUID.fromUUID(target.entityUuid()),
                            SecuredUUID.fromUUID(target.locationUuid()), certificateUuid, trackSuccessor);
        } catch (Exception e) {
            throw new LocationRenewalFailure(e);
        }
    }

    /**
     * Records a renewal call that threw. Without a tracked successor nothing was requested and the attempt counts; with
     * one the renewal was requested and its successor's outcome decides, so no attempt is counted now.
     */
    private String recordCallFailure(UUID certificateUuid, Target target, RenewalContext context, String reason) {
        CertificateRenewalLocation row = lockRow(certificateUuid, target);
        row.setStartedAt(null);
        if (row.getSuccessorUuid() != null) {
            return "location %s: the renewed certificate %s was requested, but %s"
                    .formatted(target.name(), row.getSuccessorUuid(), reason);
        }
        FailureCount failure = AutoRenewalGuards.countFailure(row.getAttempt(), context.maxAttempts(), Instant.now());
        return storeFailure(row, target, failure, reason, context.maxAttempts());
    }

    /**
     * A successor issued but not linked to the location cannot be pushed there; it is named in the history and not
     * renewed again, since the key the location generated for it cannot be recovered by another request.
     */
    private void reportWhenNotInLocation(CertificateRenewalLocation row, Target target) {
        if (!certificateLocationRepository
                .existsById(new CertificateLocationId(target.locationUuid(), row.getSuccessorUuid()))) {
            addHistory(row.getCertificateUuid(), "The renewed certificate %s was issued but is not in location %s"
                    .formatted(row.getSuccessorUuid(), target.name()));
        }
    }

    private CertificateRenewalLocation lockRow(UUID certificateUuid, Target target) {
        return renewalLocationRepository
                .findAndLock(certificateUuid, target.locationUuid())
                .orElseThrow(() -> new IllegalStateException("Renewal row of certificate %s in location %s is gone"
                        .formatted(certificateUuid, target.locationUuid())));
    }

    private String storeFailure(CertificateRenewalLocation row, Target target, FailureCount failure, String reason,
            int maxAttempts) {
        row.setAttempt(failure.attempt());
        row.setNotBefore(failure.notBefore());
        if (failure.limitReached()) {
            addHistory(row.getCertificateUuid(), "Automatic renewal in location %s stopped after %d attempts"
                    .formatted(target.name(), failure.attempt()));
        }
        return "location %s: %s (attempt %d of %d)".formatted(target.name(), reason, failure.attempt(), maxAttempts);
    }

    private static String describe(RuntimeException e, UUID certificateUuid, Target target) {
        Throwable cause = e instanceof LocationRenewalFailure ? e.getCause() : e;
        if (cause instanceof AccessDeniedException) {
            return "the trigger owner may not update the location";
        }
        if (!(cause instanceof PlatformException)) {
            logger
                    .warn("Automatic renewal of certificate {} in location {} failed unexpectedly: {}", certificateUuid,
                            target.locationUuid(), cause.getClass().getName());
            logger
                    .debug("Unexpected failure of the automatic renewal of certificate {} in location {}",
                            certificateUuid, target.locationUuid(), cause);
        }
        return PlatformException.safeMessage(cause, "unexpected error");
    }

    private void addHistory(UUID certificateUuid, String message) {
        eventHistoryService
                .addEventHistory(certificateUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, "");
    }

    private <T> T inNewTransaction(Supplier<T> work) {
        return newTransaction.execute(status -> {
            LockTimeout.bound(entityManager);
            return work.get();
        });
    }

    private record Target(UUID locationUuid, UUID entityUuid, String name) {
    }

    private record LocationClaim(boolean start, boolean reopened, String failure) {

        static final LocationClaim SKIP = new LocationClaim(false, false, null);
        static final LocationClaim PROCEED = new LocationClaim(true, false, null);
        static final LocationClaim REOPEN = new LocationClaim(false, true, null);

        static LocationClaim failed(String failure) {
            return new LocationClaim(false, false, failure);
        }
    }

    /** Carries the location service's checked failure to the failure recording. */
    private static final class LocationRenewalFailure extends RuntimeException implements PlatformException {

        LocationRenewalFailure(Exception cause) {
            super(cause.getMessage(), cause);
        }
    }
}
