package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.MessageHandlingException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.configuration.StatusPollProperties;
import com.otilm.core.messaging.jms.producers.CertificateStatusPollProducer;
import com.otilm.core.messaging.model.CertificateStatusPollMessage;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.handler.authority.AsyncOperationCapability;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.CertificateOperation;
import com.otilm.core.service.handler.authority.StatusPollResult;
import com.otilm.core.service.handler.authority.lifecycle.CertificateRevocationFinalizer;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Consumes {@link CertificateStatusPollMessage}s and drives the async-operation polling loop.
 *
 * <p>Flow per message:
 * <ol>
 *   <li>Read cert without lock. Drop if not found or no longer in a pending state.</li>
 *   <li>Call {@link AsyncOperationCapability#pollStatus} <em>outside any transaction</em>.</li>
 *   <li>On IN_PROGRESS: re-enqueue (with incremented attempt) or apply timeout.</li>
 *   <li>On COMPLETED / FAILED: open an explicit transaction, re-read with pessimistic lock,
 *       assert still pending, apply terminal transition via state machine.</li>
 * </ol>
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
    private CertificateStatusPollProducer pollProducer;
    private StatusPollProperties statusPollProperties;
    private AttributeEngine attributeEngine;
    private com.otilm.core.events.transaction.TransactionHandler transactionHandler;
    private CertificateService certificateService;
    private CertificateRevocationFinalizer revocationFinalizer;

    @Override
    public void processMessage(CertificateStatusPollMessage msg) throws MessageHandlingException {
        Certificate cert = certificateRepository.findForPollingByUuid(msg.resourceUuid()).orElse(null);
        if (cert == null) {
            logger.debug("Certificate {} not found; dropping poll message for op={}", msg.resourceUuid(), msg.op());
            return;
        }
        if (!isPendingFor(cert.getState(), msg.op())) {
            logger.debug("Certificate {} is in state {}; not pending for {}; dropping poll message",
                    msg.resourceUuid(), cert.getState(), msg.op());
            return;
        }
        if (cert.getRaProfile() == null || cert.getRaProfile().getAuthorityInstanceReference() == null) {
            logger.warn("Certificate {} has no RA profile or authority reference; dropping poll message", msg.resourceUuid());
            return;
        }

        AuthorityInstanceReference authority = cert.getRaProfile().getAuthorityInstanceReference();
        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authority);
        if (!(adapter instanceof AsyncOperationCapability async)) {
            logger.warn("Adapter for cert {} (version {}) does not implement AsyncOperationCapability — dropping poll message for op={}",
                    msg.resourceUuid(),
                    authority.getConnectorInterface() != null ? authority.getConnectorInterface().getVersion() : "unknown",
                    msg.op());
            return;
        }

        StatusPollResult status;
        try {
            status = async.pollStatus(cert, msg.op());
        } catch (ConnectorException e) {
            logger.warn("Poll status call failed for cert {} op {}: {}", msg.resourceUuid(), msg.op(), e.getMessage());
            if (isTerminalPollError(e)) {
                // Connector says the operation doesn't exist anymore or never did — no point retrying.
                // Move the cert to its failure state immediately rather than burning maxAttempts cycles.
                applyTimeout(cert, msg.op());
            } else if (msg.attempt() < statusPollProperties.scheduleFor(msg.op()).maxAttempts()) {
                pollProducer.produceMessage(new CertificateStatusPollMessage(
                        Resource.CERTIFICATE, msg.resourceUuid(), msg.op(), msg.attempt() + 1));
            } else {
                applyTimeout(cert, msg.op());
            }
            return;
        }

        if (status.status() == CertificateOperationStatus.IN_PROGRESS) {
            if (msg.attempt() < statusPollProperties.scheduleFor(msg.op()).maxAttempts()) {
                pollProducer.produceMessage(new CertificateStatusPollMessage(
                        Resource.CERTIFICATE, msg.resourceUuid(), msg.op(), msg.attempt() + 1));
            } else {
                applyTimeout(cert, msg.op());
            }
            return;
        }

        applyTerminalTransition(cert, msg.op(), status);
    }

    private void applyTerminalTransition(Certificate cert, CertificateOperation op, StatusPollResult status) {
        boolean completed = status.status() == CertificateOperationStatus.COMPLETED;
        boolean issueWithData = completed
                && (op == CertificateOperation.ISSUE || op == CertificateOperation.RENEW)
                && status.certificateData() != null && !status.certificateData().isEmpty();
        boolean revokeCompleted = completed && op == CertificateOperation.REVOKE;
        CertificateState targetState = completed ? op.terminalSuccessState() : op.terminalFailureState();
        String reason = status.reason() != null ? status.reason()
                : "Async " + op + " " + status.status().getLabel().toLowerCase();

        // Holders for post-commit side effects run OUTSIDE the lock so a slow connector doesn't
        // extend the row lock duration. applied distinguishes the no-op drop (state no longer
        // pending) from a real transition so the post-commit blocks are skipped on a drop.
        CertificateRevocationFinalizer.KeyCleanup[] revokeCleanupHolder =
                { CertificateRevocationFinalizer.KeyCleanup.NONE };
        boolean[] applied = {false};

        transactionHandler.runInNewTransaction(() -> {
            Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                    .orElseThrow(() -> new IllegalStateException("Certificate " + cert.getUuid() + " disappeared under lock"));
            if (!isPendingFor(locked.getState(), op)) {
                return;
            }
            applied[0] = true;
            if (issueWithData) {
                // Sync-path equivalence: parse + persist cert content + ISSUE event.
                // issueRequestedCertificate sets state=ISSUED via prepareIssuedCertificate (bypasses SM by design,
                // matching the sync v2 path at ClientOperationServiceImpl.issueCertificateAction:376).
                //
                // Meta is passed as empty here and written separately AFTER commit so that a meta
                // persistence failure does not roll back the state transition. The connector has
                // accepted COMPLETED — state must reflect that even if our meta write fails.
                try {
                    certificateService.issueRequestedCertificate(locked.getUuid(), status.certificateData(), java.util.List.of());
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "Failed to persist async-completed certificate " + locked.getUuid() + " (op=" + op + ")", e);
                }
            } else if (revokeCompleted) {
                // Shared revoke finalization (apply preserved attrs, capture destroyKey, clear
                // pending fields); destroyKey runs post-commit via the finalizer below.
                revokeCleanupHolder[0] = revocationFinalizer.prepareRevokeFinalization(locked);
                stateMachine.transition(locked, targetState, null, reason);
            } else {
                stateMachine.transition(locked, targetState, null, reason);
            }
        });

        if (!applied[0]) {
            return;
        }

        // Post-commit, best-effort key destruction (slow connector HTTP call) — outside the lock.
        revocationFinalizer.destroyKeyIfRequested(revokeCleanupHolder[0], cert.getUuid());

        // Post-commit meta update — outside the tx so a meta failure does not roll back the
        // state transition (state-divergence rule: once connector accepted COMPLETED, local
        // state reflects that even if downstream local writes fail).
        if (status.meta() != null && !status.meta().isEmpty()) {
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
        }
    }

    private void applyTimeout(Certificate cert, CertificateOperation op) {
        transactionHandler.runInNewTransaction(() -> {
            Certificate locked = certificateRepository.findAndLockWithAssociationsByUuid(cert.getUuid())
                    .orElseThrow(() -> new IllegalStateException("Certificate " + cert.getUuid() + " disappeared under lock"));
            if (!isPendingFor(locked.getState(), op)) {
                return;
            }
            stateMachine.transition(locked, op.terminalFailureState(), null,
                    "Operation " + op + " timed out after max poll attempts");
        });
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
        return com.otilm.core.service.handler.authority.ConnectorOperationErrorCodes.isOperationNotTracked(code)
                || code == ErrorCode.RESOURCE_NOT_FOUND;
    }

    private boolean isPendingFor(CertificateState state, CertificateOperation op) {
        return state == op.pendingState();
    }

    // SETTERs

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
    public void setPollProducer(CertificateStatusPollProducer pollProducer) {
        this.pollProducer = pollProducer;
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
    public void setTransactionHandler(com.otilm.core.events.transaction.TransactionHandler transactionHandler) {
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
