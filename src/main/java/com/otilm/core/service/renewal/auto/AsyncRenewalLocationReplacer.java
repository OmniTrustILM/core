package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocationId;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.service.LocationInternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Completes the work an automatic renewal left when an authority that issues later has issued the renewed certificate.
 * The renewal action returned when the authority accepted it, so what it asked for runs here, as the user the firing
 * that started the renewal acted as: with the platform's key, the renewed certificate replaces the old one in its
 * locations; renewed by a key-generating location, it is pushed to that location in place of the old one. A failure is
 * recorded as {@link LocationReplacementFailureRecorder} records it and starts no other renewal.
 */
@Component
public class AsyncRenewalLocationReplacer {

    private static final Logger logger = LoggerFactory.getLogger(AsyncRenewalLocationReplacer.class);
    private static final String NO_OWNER = "the trigger that renewed the certificate has no owner to act as";

    private final ClientOperationInternalService clientOperationService;
    private final LocationInternalService locationService;
    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateRenewalLocationRepository renewalLocationRepository;
    private final CertificateLocationRepository certificateLocationRepository;
    private final LocationReplacementFailureRecorder failureRecorder;
    private final AuthHelper authHelper;
    private final EntityManager entityManager;
    private final TransactionTemplate readOnlyTransaction;
    private final TransactionTemplate newTransaction;

    /** The location service reaches the trigger evaluator through the certificate service, so it is injected lazily. */
    public AsyncRenewalLocationReplacer(ClientOperationInternalService clientOperationService,
            @Lazy LocationInternalService locationService, CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateRenewalLocationRepository renewalLocationRepository,
            CertificateLocationRepository certificateLocationRepository,
            LocationReplacementFailureRecorder failureRecorder, AuthHelper authHelper, EntityManager entityManager,
            PlatformTransactionManager transactionManager) {
        this.clientOperationService = clientOperationService;
        this.locationService = locationService;
        this.renewalInfoRepository = renewalInfoRepository;
        this.renewalLocationRepository = renewalLocationRepository;
        this.certificateLocationRepository = certificateLocationRepository;
        this.failureRecorder = failureRecorder;
        this.authHelper = authHelper;
        this.entityManager = entityManager;
        this.readOnlyTransaction = new TransactionTemplate(transactionManager);
        this.readOnlyTransaction.setReadOnly(true);
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Replaces the certificate that {@code certificateUuid} renews in its locations when an automatic renewal with the
     * platform's key requested it and the old certificate is still in a location, and pushes it to each key-generating
     * location whose automatic renewal requested it while the old certificate is still there; does nothing otherwise.
     * Runs outside a transaction, as the replacement calls the locations' connectors. Never throws.
     */
    public void replaceInLocations(UUID certificateUuid) {
        PendingWork pending;
        try {
            pending = readOnlyTransaction
                    .execute(status -> new PendingWork(pendingReplacement(certificateUuid),
                            pendingLocationPushes(certificateUuid)));
        } catch (RuntimeException e) {
            logger
                    .error("Could not look up whether issued certificate {} replaces a certificate in its locations",
                            certificateUuid, e);
            return;
        }
        pending.replacement().ifPresent(replacement -> replace(certificateUuid, replacement));
        pending.locationPushes().forEach(push -> pushToLocation(certificateUuid, push));
    }

    private void replace(UUID certificateUuid, Replacement replacement) {
        logger
                .info("Automatic renewal of certificate {}: certificate {} was issued later and replaces it in its locations",
                        replacement.renewedUuid(), certificateUuid);
        if (replacement.ownerUuid() == null) {
            failureRecorder.recordFailure(replacement.renewedUuid(), certificateUuid, NO_OWNER);
            return;
        }
        try {
            authHelper.runAsUser(replacement.ownerUuid(), () -> {
                clientOperationService.replaceRenewedCertificateInLocations(replacement.renewedUuid(), certificateUuid);
                return null;
            });
        } catch (CertificateOperationException e) {
            // The replacement recorded the failure itself.
            logger.debug("Replacing certificate {} in its locations failed", replacement.renewedUuid(), e);
        } catch (NotFoundException e) {
            logger
                    .warn("Certificate {} or {} is gone; not replacing it in its locations", replacement.renewedUuid(),
                            certificateUuid);
        } catch (Exception e) {
            failureRecorder
                    .recordFailure(replacement.renewedUuid(), certificateUuid,
                            PlatformException.safeMessage(e, "unexpected error"));
        }
    }

    /**
     * Pushes the issued certificate to the location that renewed the old one and takes the old one out of that
     * location, as a renewal in the location issued at once does; then the location's renewal is complete. The old
     * entry is removed whatever relation the issued certificate has to the old one, as a location that generates a new
     * key makes it a re-key.
     */
    private void pushToLocation(UUID certificateUuid, LocationPush push) {
        logger
                .info("Automatic renewal of certificate {} in location {}: certificate {} was issued later and is pushed"
                        + " there", push.renewedUuid(), push.locationUuid(), certificateUuid);
        if (push.ownerUuid() == null) {
            failureRecorder.recordLocationFailure(push.renewedUuid(), certificateUuid, push.locationUuid(), NO_OWNER);
            return;
        }
        try {
            authHelper.runAsUser(push.ownerUuid(), () -> {
                locationService
                        .pushRequestedCertificateToLocationAction(
                                new CertificateLocationId(push.locationUuid(), certificateUuid), false);
                return null;
            });
        } catch (NotFoundException e) {
            logger
                    .warn("Certificate {} is no longer in location {}; not pushing it there", certificateUuid,
                            push.locationUuid());
            return;
        } catch (Exception e) {
            failureRecorder
                    .recordLocationFailure(push.renewedUuid(), certificateUuid, push.locationUuid(),
                            PlatformException.safeMessage(e, "unexpected error"));
            return;
        }
        removeRenewedAndComplete(push);
    }

    private void removeRenewedAndComplete(LocationPush push) {
        try {
            newTransaction.executeWithoutResult(status -> {
                certificateLocationRepository
                        .findById(new CertificateLocationId(push.locationUuid(), push.renewedUuid()))
                        .ifPresent(certificateLocationRepository::delete);
                renewalLocationRepository
                        .findAndLock(push.renewedUuid(), push.locationUuid())
                        .filter(row -> row.getCompletedAt() == null)
                        .ifPresent(row -> row.setCompletedAt(Instant.now()));
            });
            logger
                    .info("Automatic renewal of certificate {} in location {} completed", push.renewedUuid(),
                            push.locationUuid());
        } catch (RuntimeException e) {
            logger
                    .error("Could not remove certificate {} from location {} and complete its automatic renewal there",
                            push.renewedUuid(), push.locationUuid(), e);
        }
    }

    /**
     * The certificate the issued one renews, when its renewal row tracks the issued one as the successor of an
     * automatic renewal and it is still in a location: once replaced, it is in none, so the replacement runs once.
     */
    private Optional<Replacement> pendingReplacement(UUID certificateUuid) {
        Certificate certificate = entityManager.find(Certificate.class, certificateUuid);
        if (certificate == null) {
            return Optional.empty();
        }
        for (CertificateRelation relation : certificate.getPredecessorRelations()) {
            UUID renewedUuid = relation.getId().getPredecessorCertificateUuid();
            Optional<CertificateRenewalInfo> row = renewalInfoRepository
                    .findByCertificateUuid(renewedUuid)
                    .filter(renewal -> certificateUuid.equals(renewal.getRenewSuccessorUuid()));
            if (row.isPresent()) {
                if (certificateLocationRepository.findByCertificateUuid(renewedUuid).isEmpty()) {
                    return Optional.empty();
                }
                return Optional.of(new Replacement(renewedUuid, row.get().getRenewOwnerUuid()));
            }
        }
        return Optional.empty();
    }

    /**
     * The locations whose automatic renewal requested the issued certificate, linked it there, and still hold the old
     * certificate: the push removes the old one, so each location is pushed to once.
     */
    private List<LocationPush> pendingLocationPushes(UUID certificateUuid) {
        return renewalLocationRepository
                .findBySuccessorUuid(certificateUuid)
                .stream()
                .filter(row -> certificateLocationRepository
                        .existsById(new CertificateLocationId(row.getLocationUuid(), certificateUuid))
                        && certificateLocationRepository
                                .existsById(new CertificateLocationId(row.getLocationUuid(), row.getCertificateUuid())))
                .map(row -> new LocationPush(row.getCertificateUuid(), row.getLocationUuid(), row.getOwnerUuid()))
                .toList();
    }

    private record PendingWork(Optional<Replacement> replacement, List<LocationPush> locationPushes) {
    }

    private record Replacement(UUID renewedUuid, UUID ownerUuid) {
    }

    private record LocationPush(UUID renewedUuid, UUID locationUuid, UUID ownerUuid) {
    }
}
