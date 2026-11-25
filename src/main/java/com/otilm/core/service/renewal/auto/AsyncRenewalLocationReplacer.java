package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Replaces the old certificate in its locations once an authority that issues later has issued the certificate an
 * automatic renewal with the platform's key requested. The renewal action returned when the authority accepted it, so
 * the replacement it asked for runs here, as the owner of the trigger that started the renewal. A failure is recorded
 * as {@link LocationReplacementFailureRecorder} records it and starts no other renewal.
 */
@Component
public class AsyncRenewalLocationReplacer {

    private static final Logger logger = LoggerFactory.getLogger(AsyncRenewalLocationReplacer.class);

    private final ClientOperationInternalService clientOperationService;
    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateLocationRepository certificateLocationRepository;
    private final LocationReplacementFailureRecorder failureRecorder;
    private final AuthHelper authHelper;
    private final EntityManager entityManager;
    private final TransactionTemplate readOnlyTransaction;

    public AsyncRenewalLocationReplacer(ClientOperationInternalService clientOperationService,
            CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateLocationRepository certificateLocationRepository,
            LocationReplacementFailureRecorder failureRecorder, AuthHelper authHelper, EntityManager entityManager,
            PlatformTransactionManager transactionManager) {
        this.clientOperationService = clientOperationService;
        this.renewalInfoRepository = renewalInfoRepository;
        this.certificateLocationRepository = certificateLocationRepository;
        this.failureRecorder = failureRecorder;
        this.authHelper = authHelper;
        this.entityManager = entityManager;
        this.readOnlyTransaction = new TransactionTemplate(transactionManager);
        this.readOnlyTransaction.setReadOnly(true);
    }

    /**
     * Replaces the certificate that {@code certificateUuid} renews in its locations when an automatic renewal with the
     * platform's key requested it and the old certificate is still in a location, and does nothing otherwise. Runs
     * outside a transaction, as the replacement calls the locations' connectors. Never throws.
     */
    public void replaceInLocations(UUID certificateUuid) {
        Optional<Replacement> pending;
        try {
            pending = readOnlyTransaction.execute(status -> pendingReplacement(certificateUuid));
        } catch (RuntimeException e) {
            logger
                    .error("Could not look up whether issued certificate {} replaces a certificate in its locations",
                            certificateUuid, e);
            return;
        }
        if (pending.isEmpty()) {
            return;
        }
        Replacement replacement = pending.get();
        logger
                .info("Automatic renewal of certificate {}: certificate {} was issued later and replaces it in its locations",
                        replacement.renewedUuid(), certificateUuid);
        if (replacement.ownerUuid() == null) {
            failureRecorder
                    .recordFailure(replacement.renewedUuid(), certificateUuid,
                            "the trigger that renewed the certificate has no owner to act as");
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
                return Optional.of(new Replacement(renewedUuid, ownerOf(row.get().getRenewTriggerHistoryUuid())));
            }
        }
        return Optional.empty();
    }

    private UUID ownerOf(UUID triggerHistoryUuid) {
        if (triggerHistoryUuid == null) {
            return null;
        }
        TriggerHistory firing = entityManager.find(TriggerHistory.class, triggerHistoryUuid);
        if (firing == null || firing.getTriggerAssociation() == null) {
            return null;
        }
        return firing.getTriggerAssociation().getTriggeredBy();
    }

    private record Replacement(UUID renewedUuid, UUID ownerUuid) {
    }
}
