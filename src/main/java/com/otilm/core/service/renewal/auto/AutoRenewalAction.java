package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.core.certificate.type.CertificateTypeHandler;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.CommonInput;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.FailureCount;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.GuardResult;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.SuccessorStatus;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitGuardResult;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitInput;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitOutcome;
import com.otilm.core.service.renewal.auto.AutoRenewalModeResolver.ModeDecision;
import jakarta.persistence.EntityManager;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.DoubleSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The "renew certificate" trigger action. Claims the certificate under the lock of its renewal row, runs the mode's
 * handler outside any transaction, and releases or fails the claim in a third short transaction. A skip returns
 * normally; a failure throws once its state is committed, so that the trigger history records it.
 */
@Component
public class AutoRenewalAction {

    private static final Logger logger = LoggerFactory.getLogger(AutoRenewalAction.class);

    private final CertificateRenewalInfoRepository renewalInfoRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;
    private final EntityManager entityManager;
    private final TransactionTemplate newTransaction;
    private final TransactionTemplate outsideTransaction;
    private final TransactionTemplate readOnlyTransaction;
    private final Map<AutoRenewalMode, AutoRenewalHandler> handlers = new EnumMap<>(AutoRenewalMode.class);
    private final CertificateTypeHandlerRegistry typeHandlerRegistry;
    private final DoubleSupplier random;

    @Autowired
    public AutoRenewalAction(CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateRepository certificateRepository, CertificateEventHistoryInternalService eventHistoryService,
            EntityManager entityManager, PlatformTransactionManager transactionManager,
            CertificateTypeHandlerRegistry typeHandlerRegistry, List<AutoRenewalHandler> handlers) {
        this(renewalInfoRepository, certificateRepository, eventHistoryService, entityManager, transactionManager,
                typeHandlerRegistry, handlers, new SecureRandom()::nextDouble);
    }

    AutoRenewalAction(CertificateRenewalInfoRepository renewalInfoRepository,
            CertificateRepository certificateRepository, CertificateEventHistoryInternalService eventHistoryService,
            EntityManager entityManager, PlatformTransactionManager transactionManager,
            CertificateTypeHandlerRegistry typeHandlerRegistry, List<AutoRenewalHandler> handlers,
            DoubleSupplier random) {
        this.random = random;
        this.typeHandlerRegistry = typeHandlerRegistry;
        this.renewalInfoRepository = renewalInfoRepository;
        this.certificateRepository = certificateRepository;
        this.eventHistoryService = eventHistoryService;
        this.entityManager = entityManager;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.outsideTransaction = new TransactionTemplate(transactionManager);
        this.outsideTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
        this.readOnlyTransaction = new TransactionTemplate(transactionManager);
        this.readOnlyTransaction.setReadOnly(true);
        handlers.forEach(handler -> this.handlers.put(handler.mode(), handler));
    }

    /** Renews the certificate when its guards allow; throws when the renewal failed or cannot run. */
    public void perform(Certificate certificate, TriggerContext context) throws RuleException {
        UUID certificateUuid = certificate.getUuid();
        Claim claim = newTransaction.execute(status -> claim(certificateUuid, context, Instant.now()));
        switch (Objects.requireNonNull(claim)) {
            case Skip(String reason) -> logger
                    .debug("Automatic renewal of certificate {} by trigger {} skipped: {}", certificateUuid,
                            context.triggerUuid(), reason);
            case Failure(String message) -> {
                logger
                        .info("Automatic renewal of certificate {} by trigger {} failed: {}", certificateUuid,
                                context.triggerUuid(), message);
                throw new RuleException(message);
            }
            case Start start -> renew(certificateUuid, context, start);
        }
    }

    private Set<CertificateOperation> typeOperations(Certificate certificate) {
        return typeHandlerRegistry
                .find(certificate.getCertificateType().getCode())
                .map(CertificateTypeHandler::supportedOperations)
                .orElseGet(() -> EnumSet.noneOf(CertificateOperation.class));
    }

    private Claim claim(UUID certificateUuid, TriggerContext context, Instant now) {
        // Never waits: the holder may be another firing, or a transaction this thread suspended to claim, such as the
        // trigger evaluation after a set-field action switched the RA profile. The next firing tries again.
        Optional<CertificateRenewalInfo> locked = renewalInfoRepository
                .findAndLockByCertificateUuidSkipLocked(certificateUuid);
        Optional<Certificate> found = certificateRepository.findById(certificateUuid);
        if (locked.isEmpty() || found.isEmpty()) {
            return new Skip("the certificate has no renewal window, or its renewal state is locked");
        }
        CertificateRenewalInfo row = locked.get();
        Certificate certificate = found.get();
        RaProfile raProfile = certificate.getRaProfile();
        boolean enabled = raProfile != null && raProfile.isAutoRenewalEnabled();
        AutoRenewalMode mode = null;
        if (enabled) {
            ModeDecision decision = AutoRenewalModeResolver
                    .resolve(certificate, certificateRepository.hasLocationRenewals(certificateUuid),
                            typeOperations(certificate));
            storeBlockedReason(row, decision);
            mode = decision.mode();
        }
        GuardResult common = AutoRenewalGuards
                .common(new CommonInput(enabled, mode, row.getRenewAt(), row.getWindowStart(), row.getWindowEnd()), now,
                        random.getAsDouble());
        if (common.renewAt() != null && !common.renewAt().equals(row.getRenewAt())) {
            row.setRenewAt(common.renewAt());
            logger.debug("Certificate {} is renewed automatically from {}", certificateUuid, common.renewAt());
        }
        if (!common.proceeds()) {
            return new Skip(common.skip().name());
        }
        if (context.ownerUuid() == null) {
            return new Failure("The trigger that renews the certificate automatically has no owner to act as");
        }
        if (!handlers.containsKey(mode)) {
            return new Failure("Automatic renewal is not available for mode %s".formatted(mode.getLabel()));
        }
        if (AutoRenewalGuards.markerHeld(row.getRenewStartedAt(), now)) {
            return new Skip("another firing is renewing the certificate");
        }
        int maxAttempts = raProfile.getAutoRenewalMaxAttempts();
        if (mode == AutoRenewalMode.ILM_KEY) {
            Optional<Claim> blocked = applyUnitGuards(certificate, row, maxAttempts, now);
            if (blocked.isPresent()) {
                return blocked.get();
            }
        }
        row.setRenewStartedAt(now);
        return new Start(mode, maxAttempts, now);
    }

    /** The certificate itself is the unit of work when the platform holds its key. */
    private Optional<Claim> applyUnitGuards(Certificate certificate, CertificateRenewalInfo row, int maxAttempts,
            Instant now) {
        UUID successorUuid = row.getRenewSuccessorUuid();
        SuccessorStatus successor = successorUuid == null
                ? SuccessorStatus.NONE
                : SuccessorStatus
                        .of(certificateRepository.findById(successorUuid).map(Certificate::getState).orElse(null));
        boolean foreignRenewal = certificate
                .getSuccessorRelations()
                .stream()
                .map(CertificateRelation::getId)
                .anyMatch(id -> !id.getSuccessorCertificateUuid().equals(successorUuid));
        UnitGuardResult result = AutoRenewalGuards
                .unit(new UnitInput(false, successor, foreignRenewal, row.getRenewAttempt(), row.getRenewNotBefore(),
                        maxAttempts), now);
        if (result.failure() != null) {
            row.setRenewSuccessorUuid(null);
            String message = "The renewed certificate %s was rejected, failed or removed".formatted(successorUuid);
            storeFailure(row, result.failure(), message, maxAttempts);
            return Optional.of(new Failure(message));
        }
        if (result.outcome() != UnitOutcome.START) {
            return Optional.of(new Skip(result.outcome().name()));
        }
        return Optional.empty();
    }

    private void renew(UUID certificateUuid, TriggerContext context, Start start) throws RuleException {
        AutoRenewalHandler handler = handlers.get(start.mode());
        RenewalContext renewalContext = new RenewalContext(context.ownerUuid(), start.maxAttempts(), start.now(),
                context.triggerHistoryUuid(), context.executionUuid());
        logger
                .info("Automatic renewal of certificate {} by trigger {} starts in mode {}", certificateUuid,
                        context.triggerUuid(), start.mode().getLabel());
        try {
            outsideTransaction.executeWithoutResult(status -> runHandler(handler, certificateUuid, renewalContext));
        } catch (RuntimeException e) {
            String reason = PlatformException.safeMessage(e, "unexpected error");
            if (!(e instanceof PlatformException)) {
                logger
                        .warn("Automatic renewal of certificate {} failed unexpectedly in mode {}: {}", certificateUuid,
                                start.mode().getLabel(), e.getClass().getName());
                logger.debug("Unexpected failure of the automatic renewal of certificate {}", certificateUuid, e);
            }
            String message = newTransaction.execute(status -> recordFailure(certificateUuid, start, reason));
            logger
                    .info("Automatic renewal of certificate {} by trigger {} failed: {}", certificateUuid,
                            context.triggerUuid(), reason);
            throw new RuleException(message);
        }
        newTransaction.executeWithoutResult(status -> release(certificateUuid));
        logger
                .info("Automatic renewal of certificate {} by trigger {} started", certificateUuid,
                        context.triggerUuid());
    }

    /**
     * Runs the handler with the caller's transaction suspended and none of its own, as the renewal it starts calls out
     * to connectors; the handler keeps its reads and writes in short transactions of their own. The certificate is read
     * in a short transaction too and handed over detached, so no lazy load holds a connection across a call.
     */
    private void runHandler(AutoRenewalHandler handler, UUID certificateUuid, RenewalContext renewalContext) {
        Certificate certificate = Optional
                .ofNullable(
                        readOnlyTransaction.execute(status -> entityManager.find(Certificate.class, certificateUuid)))
                .orElseThrow(
                        () -> new IllegalStateException("Certificate %s no longer exists".formatted(certificateUuid)));
        try {
            handler.renew(certificate, renewalContext);
        } catch (AutoRenewalException e) {
            throw new HandlerFailure(e);
        }
    }

    /**
     * Records a handler failure and answers the message for the trigger history. When the platform holds the key, an
     * attempt counts only when no successor was requested: a successor the handler tracked before failing was
     * requested, so its own outcome decides at a later firing.
     */
    private String recordFailure(UUID certificateUuid, Start start, String reason) {
        String message = "Automatic renewal failed: " + reason;
        Optional<CertificateRenewalInfo> locked = renewalInfoRepository.findAndLockByCertificateUuid(certificateUuid);
        if (locked.isEmpty()) {
            return message;
        }
        CertificateRenewalInfo row = locked.get();
        row.setRenewStartedAt(null);
        if (start.mode() != AutoRenewalMode.ILM_KEY) {
            addHistory(certificateUuid, message);
        } else if (row.getRenewSuccessorUuid() != null) {
            message = "Automatic renewal failed: the renewed certificate %s was requested, but %s"
                    .formatted(row.getRenewSuccessorUuid(), reason);
            addHistory(certificateUuid, message);
        } else {
            FailureCount failure = AutoRenewalGuards
                    .countFailure(row.getRenewAttempt(), start.maxAttempts(), Instant.now());
            storeFailure(row, failure, message, start.maxAttempts());
        }
        return message;
    }

    private void release(UUID certificateUuid) {
        renewalInfoRepository
                .findAndLockByCertificateUuid(certificateUuid)
                .ifPresent(row -> row.setRenewStartedAt(null));
    }

    private void storeFailure(CertificateRenewalInfo row, FailureCount failure, String message, int maxAttempts) {
        row.setRenewAttempt(failure.attempt());
        row.setRenewNotBefore(failure.notBefore());
        addHistory(row.getCertificateUuid(),
                "%s (attempt %d of %d)".formatted(message, failure.attempt(), maxAttempts));
        if (failure.limitReached()) {
            addHistory(row.getCertificateUuid(),
                    "Automatic renewal stopped after %d failed attempts".formatted(failure.attempt()));
        }
    }

    /** Stores why the certificate cannot be renewed, writing it to the history only when it changes. */
    private void storeBlockedReason(CertificateRenewalInfo row, ModeDecision decision) {
        String reason = decision.mode() == AutoRenewalMode.NONE ? decision.blockedReason() : null;
        if (Objects.equals(reason, row.getRenewBlockedReason())) {
            return;
        }
        row.setRenewBlockedReason(reason);
        if (reason != null) {
            addHistory(row.getCertificateUuid(), "Automatic renewal is not possible: " + reason);
        }
    }

    private void addHistory(UUID certificateUuid, String message) {
        eventHistoryService
                .addEventHistory(certificateUuid, CertificateEvent.RENEW, CertificateEventStatus.FAILED, message, "");
    }

    private sealed interface Claim permits Skip, Failure, Start {
    }

    private record Skip(String reason) implements Claim {
    }

    private record Failure(String message) implements Claim {
    }

    private record Start(AutoRenewalMode mode, int maxAttempts, Instant now) implements Claim {
    }

    /** Carries a handler's checked failure out of the transaction callback. */
    private static final class HandlerFailure extends RuntimeException implements PlatformException {

        HandlerFailure(AutoRenewalException cause) {
            super(cause.getMessage(), cause);
        }
    }
}
