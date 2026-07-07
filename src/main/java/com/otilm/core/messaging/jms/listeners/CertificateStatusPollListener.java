package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.ConnectorOperationErrorCodes;
import com.otilm.core.service.handler.authority.StatusPollResult;
import com.otilm.core.service.handler.authority.lifecycle.CertificateRevocationFinalizer;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.writer.registration.CertificateRegistrationWriter;
import com.otilm.core.service.writer.statuspoll.CertificateStatusPollWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Consumes {@link CertificateStatusPollMessage}s and drives the async-operation polling loop.
 *
 * <p>Flow per message:
 * <ol>
 *   <li>Read cert without lock. Drop (and delete the poll row) if not found or no longer pending.</li>
 *   <li>Call {@link AsyncOperationCapability#pollStatus} <em>outside any transaction</em>.</li>
 *   <li>On IN_PROGRESS: leave the poll row in place — the {@code certificate_status_poll} sweep has
 *       already advanced its {@code next_poll_at}, so the next poll fires when due. Only when the last
 *       allowed attempt is reached does this apply a timeout.</li>
 *   <li>On COMPLETED / FAILED: open an explicit transaction, re-read with pessimistic lock,
 *       assert still pending, apply terminal transition via state machine.</li>
 * </ol>
 *
 * <p>The cadence/backoff is owned by the due-time table and its sweep, not by this listener; the listener
 * only decides the terminal/timeout outcome and deletes the poll row once the operation is resolved.</p>
 *
 * <p>No {@code @Transactional} on {@link #processMessage} — the adapter call must never hold
 * a database transaction or row lock.</p>
 */
@Component
public class CertificateStatusPollListener implements MessageProcessor<CertificateStatusPollMessage> {

    private static final Logger logger = LoggerFactory.getLogger(CertificateStatusPollListener.class);

    private CertificateRepository certificateRepository;
    private AuthorityProviderAdapterFactory adapterFactory;
    private CertificateStateMachine stateMachine;
    private CertificateStatusPollWriter pollWriter;
    private CertificateRegistrationWriter registrationWriter;
    private StatusPollProperties statusPollProperties;
    private AttributeEngine attributeEngine;
    private TransactionHandler transactionHandler;
    private CertificateService certificateService;
    private CertificateRevocationFinalizer revocationFinalizer;

    @Override
    public void processMessage(CertificateStatusPollMessage msg) throws MessageHandlingException {
        Certificate cert = certificateRepository.findForPollingByUuid(msg.resourceUuid()).orElse(null);
        if (cert == null) {
            logger.debug("Certificate {} not found; dropping poll for op={}", msg.resourceUuid(), msg.op());
            pollWriter.delete(msg.resourceUuid());
            return;
        }
        if (!isPendingFor(cert.getState(), msg.op())) {
            logger.debug("Certificate {} is in state {}; not pending for {}; dropping poll",
                    msg.resourceUuid(), cert.getState(), msg.op());
            pollWriter.delete(msg.resourceUuid());
            return;
        }
        if (cert.getRaProfile() == null || cert.getRaProfile().getAuthorityInstanceReference() == null) {
            logger.warn("Certificate {} has no RA profile or authority reference; abandoning poll", msg.resourceUuid());
            pollWriter.delete(msg.resourceUuid());
            return;
        }

        AuthorityInstanceReference authority = cert.getRaProfile().getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);
        if (!(adapter instanceof AsyncOperationCapability async)) {
            logger.warn("Adapter for cert {} (version {}) does not implement AsyncOperationCapability — abandoning poll for op={}",
                    msg.resourceUuid(),
                    authority.getConnectorInterface() != null ? authority.getConnectorInterface().getVersion() : "unknown",
                    msg.op());
            pollWriter.delete(msg.resourceUuid());
            return;
        }

        StatusPollResult status;
        try {
            status = async.pollStatus(cert, msg.op());
        } catch (ConnectorException e) {
            logger.warn("Poll status call failed for cert {} op {}: {}", msg.resourceUuid(), msg.op(), e.getMessage());
            if (isTerminalPollError(e)) {
                applyFailure(cert, msg.op(), "Connector reports the " + msg.op() + " operation is no longer tracked");
            } else if (isLastAttempt(msg)) {
                applyFailure(cert, msg.op(), timeoutReason(msg.op()));
            }
            // Otherwise transient — leave the poll row; the sweep has already rescheduled the retry.
            return;
        }

        if (status.status() == CertificateOperationStatus.IN_PROGRESS) {
            if (isLastAttempt(msg)) {
                applyFailure(cert, msg.op(), timeoutReason(msg.op()));
            }
            // Otherwise still in progress — leave the poll row for the sweep's next due tick.
            return;
        }

        applyTerminalTransition(cert, msg.op(), status);
    }

    /** True when this poll is the final attempt allowed by the backoff schedule for the operation. */
    private boolean isLastAttempt(CertificateStatusPollMessage msg) {
        return msg.attempt() + 1 >= statusPollProperties.scheduleFor(msg.op()).maxAttempts();
    }

    private static String timeoutReason(CertificateOperation op) {
        return "Operation " + op + " timed out after the maximum poll attempts";
    }

    private void applyTerminalTransition(Certificate cert, CertificateOperation op, StatusPollResult status) {
        // Hold the row lock only for the local transition; the post-commit side effects run outside it.
        Resolution resolution;
        try {
            resolution = transactionHandler.runInNewTransaction(() -> {
                Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                        .orElseThrow(() -> new IllegalStateException("Certificate " + cert.getUuid() + " disappeared under lock"));
                if (!isPendingFor(locked.getState(), op)) {
                    return Resolution.NOT_APPLIED;
                }
                return Resolution.applied(applyResolvedState(locked, op, status));
            });
        } catch (DeterministicPersistException e) {
            // Deterministic persist failure: the locked tx rolled back, so fail fast to the failure state
            // instead of re-polling to timeout.
            applyFailure(cert, op, e.getMessage());
            return;
        } catch (RuntimeException e) {
            // Add cert/op context — the JMS adapter logs only the bare exception. The rollback left the poll
            // row, so the sweep retries (a transient blip recovers; a should-not-happen error retries to maxAttempts).
            throw new IllegalStateException(
                    "Async " + op + " terminal transition for cert " + cert.getUuid()
                            + " did not apply; poll row left for the sweep to retry", e);
        }

        if (resolution.applied()) {
            // Run post-commit side effects before the delete so a transient delete failure can't skip them
            // (a completed REVOKE must still destroy the key).
            revocationFinalizer.destroyKeyIfRequested(resolution.keyCleanup(), cert.getUuid());
            updateMetaAfterCommit(cert, op, status);
        }
        // Stop polling — safe even when a racing actor resolved it: the unique constraint means one poll row per cert.
        stopPolling(cert, op);
    }

    /** Outcome of the locked terminal transition: whether it was applied, and any post-commit key cleanup. */
    private record Resolution(boolean applied, CertificateRevocationFinalizer.KeyCleanup keyCleanup) {
        static final Resolution NOT_APPLIED = new Resolution(false, CertificateRevocationFinalizer.KeyCleanup.NONE);
        static Resolution applied(CertificateRevocationFinalizer.KeyCleanup keyCleanup) {
            return new Resolution(true, keyCleanup);
        }
    }

    /**
     * Applies the terminal state inside the held lock and returns the post-commit key-cleanup decision
     * (NONE unless a revoke completed). Each branch is a single guarded outcome.
     */
    private CertificateRevocationFinalizer.KeyCleanup applyResolvedState(
            Certificate locked, CertificateOperation op, StatusPollResult status) {
        boolean completed = status.status() == CertificateOperationStatus.COMPLETED;
        boolean isIssueOrRenew = op == CertificateOperation.ISSUE || op == CertificateOperation.RENEW;

        if (completed && isIssueOrRenew) {
            if (status.certificateData() != null && !status.certificateData().isEmpty()) {
                persistIssuedCertificate(locked, op, status);
            } else {
                // COMPLETED for issue/renew with no certificate content is self-contradictory: we cannot
                // reach ISSUED without persisting a certificate, so fail it rather than reach an empty ISSUED.
                stateMachine.transition(locked, op.terminalFailureState(), null,
                        "Async " + op + " reported COMPLETED but connector returned no certificate data");
            }
            return CertificateRevocationFinalizer.KeyCleanup.NONE;
        }

        if (completed && op == CertificateOperation.REVOKE) {
            // destroyKey is captured here and run post-commit by the finalizer (outside the lock).
            CertificateRevocationFinalizer.KeyCleanup cleanup = revocationFinalizer.prepareRevokeFinalization(locked);
            stateMachine.transition(locked, op.terminalSuccessState(), null, reasonFor(op, status));
            return cleanup;
        }

        // Everything else: failures go to the failure state; a COMPLETED REGISTER goes to REGISTERED.
        if (op == CertificateOperation.REVOKE) {
            // A failed/cancelled REVOKE returns to ISSUED — clear pending-revoke fields so it doesn't look in-flight.
            revocationFinalizer.clearPendingRevokeFields(locked);
        }
        CertificateState targetState = completed ? op.terminalSuccessState() : op.terminalFailureState();
        stateMachine.transition(locked, targetState, null, reasonFor(op, status));
        return CertificateRevocationFinalizer.KeyCleanup.NONE;
    }

    /**
     * Sync-path equivalence for a completed issue/renew: parse + persist cert content + ISSUE event.
     * {@code issueRequestedCertificate} stamps the cert fields and drives the {@code PENDING_ISSUE -> ISSUED}
     * transition through the state machine (same path as the sync v2 issue). Meta is passed empty here and
     * written after commit so a meta-persistence failure does not roll
     * back the transition — the connector accepted COMPLETED, so state must reflect that.
     */
    private void persistIssuedCertificate(Certificate locked, CertificateOperation op, StatusPollResult status) {
        try {
            certificateService.issueRequestedCertificate(locked.getUuid(), status.certificateData(), List.of());
        } catch (Exception e) {
            if (isTransient(e)) {
                // Propagate so the locked tx rolls back and the row survives; the sweep re-polls (the adapter
                // swallows the throw, so retry is sweep-driven, not JMS redelivery).
                throw new IllegalStateException(
                        "Transient failure persisting async-completed certificate " + locked.getUuid() + " (op=" + op + ")", e);
            }
            // Deterministic failure (parse error, already-exists on redelivery, ...): retrying hits the same
            // error, so fail fast. The authority did complete the operation, so the reason points at the
            // local/upstream divergence to reconcile (raw cause is logged, not surfaced).
            logger.warn("Async {} for cert {} completed at the authority but could not be persisted (deterministic): {}",
                    op, locked.getUuid(), e.getMessage(), e);
            throw new DeterministicPersistException(
                    "Async " + op + " completed at the authority but the certificate could not be persisted; reconcile manually");
        }
    }

    private static boolean isTransient(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof TransientDataAccessException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Non-recoverable persist failure after a COMPLETED poll — fail the operation fast instead of looping to
     * timeout. Implements {@link PlatformException} (its message is shaped, no raw cause) per the rule that every
     * core exception be wire-safe-gateable, even though this one is caught internally and never reaches a caller.
     */
    private static final class DeterministicPersistException extends RuntimeException implements PlatformException {
        DeterministicPersistException(String message) {
            super(message);
        }
    }

    private static String reasonFor(CertificateOperation op, StatusPollResult status) {
        return status.reason() != null ? status.reason()
                : "Async " + op + " " + status.status().getLabel().toLowerCase();
    }

    /**
     * Best-effort post-commit meta write, outside the tx (state-divergence rule: once the connector accepted
     * COMPLETED, local state reflects that even if this downstream write fails).
     */
    private void updateMetaAfterCommit(Certificate cert, CertificateOperation op, StatusPollResult status) {
        if (status.meta() == null || status.meta().isEmpty()) {
            return;
        }
        AuthorityInstanceReference metaAuthority = cert.getRaProfile() != null
                ? cert.getRaProfile().getAuthorityInstanceReference()
                : null;
        if (metaAuthority == null) {
            logger.warn("Cannot update meta for cert {} — authority not resolvable", cert.getUuid());
            return;
        }
        try {
            attributeEngine.updateMetadataAttributes(
                    status.meta(),
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                            .connector(metaAuthority.getConnectorUuid())
                            .build());
        } catch (Exception e) {
            logger.warn("Failed to update metadata attributes for cert {} after {} {}; transition already committed",
                    cert.getUuid(), op, status.status(), e);
        }
        if (op == CertificateOperation.REGISTER && status.status() == CertificateOperationStatus.COMPLETED) {
            refreshRegistrationBinding(cert, status);
        }
    }

    /**
     * A completed async REGISTER may supersede the 202 tracking handle with the final CA handle; the binding must
     * carry the latest one for the later issue to replay. Best-effort — on failure the binding keeps the 202 handle.
     */
    private void refreshRegistrationBinding(Certificate cert, StatusPollResult status) {
        try {
            registrationWriter.upsert(cert.getUuid(), status.meta());
        } catch (RuntimeException e) {
            logger.warn("Failed to refresh the register->issue binding meta for cert {}; "
                    + "the binding keeps the tracking handle from the 202 response", cert.getUuid(), e);
        }
    }

    /**
     * Moves a still-pending operation to its terminal failure state with the given audit reason and stops
     * polling it. Used both when polls are exhausted (timeout) and when the connector reports the operation
     * is no longer tracked — the reason distinguishes the two in the certificate history.
     */
    private void applyFailure(Certificate cert, CertificateOperation op, String reason) {
        transactionHandler.runInNewTransaction(() -> {
            Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                    .orElseThrow(() -> new IllegalStateException("Certificate " + cert.getUuid() + " disappeared under lock"));
            if (!isPendingFor(locked.getState(), op)) {
                return;
            }
            // A failed revoke returns to ISSUED — clear pending-revoke params (see applyResolvedState).
            if (op == CertificateOperation.REVOKE) {
                revocationFinalizer.clearPendingRevokeFields(locked);
            }
            stateMachine.transition(locked, op.terminalFailureState(), null, reason);
        });
        // Resolved (failed, or already resolved by a racing actor) — stop polling it.
        stopPolling(cert, op);
    }


    /** Deletes the cert's poll row to stop polling, best-effort; a failed delete is dropped by the next poll. */
    private void stopPolling(Certificate cert, CertificateOperation op) {
        try {
            pollWriter.delete(cert.getUuid());
        } catch (RuntimeException e) {
            logger.warn("Failed to delete resolved poll row for cert {} ({}); it will be dropped on the next poll",
                    cert.getUuid(), op, e);
        }
    }

    /**
     * Connector-side error codes that mean retrying the status poll is pointless: the
     * operation either never existed at the upstream CA or has been forgotten. Treat as
     * terminal and move the cert to its failure state immediately. Other ConnectorExceptions
     * (network, 5xx, transient) remain retryable up to maxAttempts.
     */
    private static boolean isTerminalPollError(ConnectorException e) {
        if (!(e instanceof ConnectorProblemException problem) || problem.getProblemDetail() == null) {
            return false;
        }
        ErrorCode code = problem.getProblemDetail().getErrorCode();
        return ConnectorOperationErrorCodes.isOperationNotTracked(code)
                || code == ErrorCode.RESOURCE_NOT_FOUND;
    }

    private boolean isPendingFor(CertificateState state, CertificateOperation op) {
        return state == op.pendingState();
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setAdapterFactory(AuthorityProviderAdapterFactory adapterFactory) {
        this.adapterFactory = adapterFactory;
    }

    @Autowired
    public void setStateMachine(CertificateStateMachine stateMachine) {
        this.stateMachine = stateMachine;
    }

    @Autowired
    public void setPollWriter(CertificateStatusPollWriter pollWriter) {
        this.pollWriter = pollWriter;
    }

    @Autowired
    public void setRegistrationWriter(CertificateRegistrationWriter registrationWriter) {
        this.registrationWriter = registrationWriter;
    }

    @Autowired
    public void setStatusPollProperties(StatusPollProperties statusPollProperties) {
        this.statusPollProperties = statusPollProperties;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setRevocationFinalizer(CertificateRevocationFinalizer revocationFinalizer) {
        this.revocationFinalizer = revocationFinalizer;
    }
}
