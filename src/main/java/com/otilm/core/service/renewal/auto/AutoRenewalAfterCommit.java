package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.RuleException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.service.TriggerInternalService;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Starts the "renew certificate" trigger action once the caller's transaction has completed with a commit, so the event
 * that fired it holds no connection while the renewal calls out to connectors. It runs after every after-commit
 * callback of that transaction, such as cache evictions, on the same thread and as the trigger owner the caller acted
 * as; a rolled back transaction starts nothing. A failure is added to the firing's trigger history in a transaction of
 * its own; a skip leaves no record.
 */
@Component
public class AutoRenewalAfterCommit {

    private static final Logger logger = LoggerFactory.getLogger(AutoRenewalAfterCommit.class);
    static final String UNEXPECTED_FAILURE = "Automatic renewal failed: unexpected error";

    private final AutoRenewalAction action;
    private final TriggerInternalService triggerService;
    private final TransactionTemplate newTransaction;

    /** The trigger service reaches the trigger evaluator, which uses this component, so it is injected lazily. */
    public AutoRenewalAfterCommit(AutoRenewalAction action, @Lazy TriggerInternalService triggerService,
            PlatformTransactionManager transactionManager) {
        this.action = action;
        this.triggerService = triggerService;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Performs the action after the caller's transaction commits, or at once, throwing its failure, when the caller has
     * no transaction.
     */
    public void perform(Certificate certificate, TriggerContext context) throws RuleException {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            action.perform(certificate, context);
            return;
        }
        Authentication owner = SecurityContextHolder.getContext().getAuthentication();
        Map<String, String> ownerActor = LoggingHelper.snapshotActorInfo();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_COMMITTED) {
                    performAs(owner, ownerActor, certificate, context);
                }
            }
        });
    }

    private void performAs(Authentication owner, Map<String, String> ownerActor, Certificate certificate,
            TriggerContext context) {
        SecurityContext callerContext = SecurityContextHolder.getContext();
        boolean callerAuthenticated = callerContext.getAuthentication() != null;
        Map<String, String> callerActor = LoggingHelper.snapshotActorInfo();
        try {
            SecurityContext ownerContext = SecurityContextHolder.createEmptyContext();
            ownerContext.setAuthentication(owner);
            SecurityContextHolder.setContext(ownerContext);
            LoggingHelper.restoreActorInfo(ownerActor);
            action.perform(certificate, context);
        } catch (RuleException e) {
            recordFailure(certificate.getUuid(), context, e.getMessage());
        } catch (RuntimeException e) {
            logger
                    .error("Automatic renewal of certificate {} failed unexpectedly after the event committed",
                            certificate.getUuid(), e);
            recordFailure(certificate.getUuid(), context, UNEXPECTED_FAILURE);
        } finally {
            if (callerAuthenticated) {
                SecurityContextHolder.setContext(callerContext);
            } else {
                SecurityContextHolder.clearContext();
            }
            LoggingHelper.restoreActorInfo(callerActor);
        }
    }

    private void recordFailure(UUID certificateUuid, TriggerContext context, String message) {
        if (context.triggerHistoryUuid() == null) {
            return;
        }
        try {
            newTransaction.executeWithoutResult(status -> {
                triggerService
                        .createTriggerHistoryRecord(context.triggerHistoryUuid(), null, context.executionUuid(),
                                message);
                triggerService.setTriggerHistoryActionsPerformedFalse(context.triggerHistoryUuid());
            });
        } catch (RuntimeException e) {
            logger
                    .warn("Could not add the failed automatic renewal of certificate {} to trigger history {}",
                            certificateUuid, context.triggerHistoryUuid());
            logger.debug("Trigger history record failed", e);
        }
    }
}
