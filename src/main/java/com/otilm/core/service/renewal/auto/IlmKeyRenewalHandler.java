package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.ClientOperationInternalService;
import jakarta.persistence.EntityManager;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Renews a certificate whose key the platform holds: once, with that key and the stored request, and with the renewed
 * certificate replacing the old one in every location that holds it. The successor is stored on the renewal row before
 * its renewal is queued, so it stays tracked whatever fails after Core committed it.
 */
@Component
public class IlmKeyRenewalHandler implements AutoRenewalHandler {

    private static final Logger logger = LoggerFactory.getLogger(IlmKeyRenewalHandler.class);

    private final ClientOperationInternalService clientOperationService;
    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final EntityManager entityManager;
    private final TransactionTemplate newTransaction;
    private final TransactionTemplate readOnlyTransaction;

    /** The client operation service reaches the trigger evaluator, which reaches this handler, so it is lazy. */
    public IlmKeyRenewalHandler(@Lazy ClientOperationInternalService clientOperationService,
            CertificateRenewalInfoRepository renewalInfoRepository, EntityManager entityManager,
            PlatformTransactionManager transactionManager) {
        this.clientOperationService = clientOperationService;
        this.renewalInfoRepository = renewalInfoRepository;
        this.entityManager = entityManager;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.readOnlyTransaction = new TransactionTemplate(transactionManager);
        this.readOnlyTransaction.setReadOnly(true);
    }

    @Override
    public AutoRenewalMode mode() {
        return AutoRenewalMode.ILM_KEY;
    }

    @Override
    public void renew(Certificate certificate, RenewalContext context) throws AutoRenewalException {
        UUID certificateUuid = certificate.getUuid();
        RenewTarget target = readOnlyTransaction.execute(status -> renewTarget(certificateUuid));
        ClientCertificateRenewRequestDto request = ClientCertificateRenewRequestDto.builder().build();
        request.setReplaceInLocations(true);
        ClientCertificateDataResponseDto response;
        try {
            response = clientOperationService
                    .renewCertificate(SecuredParentUUID.fromUUID(target.authorityUuid()),
                            SecuredUUID.fromUUID(target.raProfileUuid()), certificateUuid.toString(), request, null,
                            successorUuid -> trackSuccessor(certificateUuid, successorUuid, context));
        } catch (AccessDeniedException e) {
            throw new AutoRenewalException("the trigger owner may not renew the certificate", e);
        } catch (Exception e) {
            if (!(e instanceof PlatformException)) {
                logger
                        .warn("Automatic renewal of certificate {} failed unexpectedly: {}", certificateUuid,
                                e.getClass().getName());
                logger.debug("Unexpected failure of the automatic renewal of certificate {}", certificateUuid, e);
            }
            throw new AutoRenewalException(PlatformException.safeMessage(e, "unexpected error"), e);
        }
        // Core returns without queuing a request that compliance rejects; tracking it lets the next firing count it.
        UUID successorUuid = UUID.fromString(response.getUuid());
        trackSuccessor(certificateUuid, successorUuid, context);
        logger.info("Automatic renewal of certificate {} requested certificate {}", certificateUuid, successorUuid);
    }

    private RenewTarget renewTarget(UUID certificateUuid) {
        RaProfile raProfile = entityManager.find(Certificate.class, certificateUuid).getRaProfile();
        return new RenewTarget(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid());
    }

    private void trackSuccessor(UUID certificateUuid, UUID successorUuid, RenewalContext context) {
        newTransaction.executeWithoutResult(status -> {
            LockTimeout.bound(entityManager);
            CertificateRenewalInfo row = renewalInfoRepository
                    .findAndLockByCertificateUuid(certificateUuid)
                    .orElseThrow(() -> new IllegalStateException(
                            "Renewal row of certificate %s is gone".formatted(certificateUuid)));
            row.setRenewSuccessorUuid(successorUuid);
            row.setRenewTriggerHistoryUuid(context.triggerHistoryUuid());
            row.setRenewExecutionUuid(context.executionUuid());
            row.setRenewOwnerUuid(context.ownerUuid());
        });
    }

    private record RenewTarget(UUID authorityUuid, UUID raProfileUuid) {
    }
}
