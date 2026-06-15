package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

/**
 * Gates and audits every {@link Certificate} state change.
 *
 * <p>Responsibilities (and only these):
 * <ol>
 *   <li>Validate (from, to) pair against {@link CertificateStateTransition} table — throw on miss</li>
 *   <li>Mutate cert.state + persist via repository</li>
 *   <li>Write audit history entry via {@link CertificateEventHistoryInternalService}</li>
 * </ol>
 *
 * <p>SM does NOT call entityManager.flush() — callers can mutate the same entity post-transition
 * within the same transaction; mutations flush at commit (Hibernate dirty-tracking).</p>
 *
 * <p>SM does NOT drive the side effects (location cleanup, predecessor-relation deletion, dual-cert
 * event history) that the existing v2 client-operations service bundles into its failure handling.
 * The caller remains responsible for those.</p>
 *
 * <p>The SM is intentionally lock-free. Concurrency on a single certificate is the caller's
 * responsibility: operator paths and the async poll listener acquire a pessimistic lock
 * (findAndLockWithAssociationsByUuid) and re-assert state before calling transition(), so the
 * read-modify-write here runs under that lock. See the activation slice for the locked call sites.</p>
 *
 * <p>SM governs state CHANGES, not initial assignment at row creation. Paths that set state
 * directly on a new Certificate (CertificateServiceImpl.createPlaceholder,
 * CertificateUtil.prepareIssuedCertificate) bypass the SM by design.</p>
 */
@Service
public class CertificateStateMachine {

    private final CertificateRepository certificateRepository;
    private final CertificateEventHistoryInternalService eventHistoryService;

    public CertificateStateMachine(CertificateRepository certificateRepository,
                                   CertificateEventHistoryInternalService eventHistoryService) {
        this.certificateRepository = certificateRepository;
        this.eventHistoryService = eventHistoryService;
    }

    /** Convenience overload: the audit event and the reason message are both auto-derived — the
     *  event from the transition row's {@code defaultAuditEvent}, the message from the from/to states. */
    @Transactional
    public void transition(Certificate cert, CertificateState toState) {
        applyTransition(cert, toState, null, null);
    }

    /**
     * @param auditEventOverride if non-null, overrides the row's defaultAuditEvent
     * @param reasonMessage if non-null, used as the audit-history message; otherwise auto-generated
     */
    @Transactional
    public void transition(Certificate cert, CertificateState toState,
                           @Nullable CertificateEvent auditEventOverride,
                           @Nullable String reasonMessage) {
        applyTransition(cert, toState, auditEventOverride, reasonMessage);
    }

    /** Private so the {@code @Transactional} public overloads are reached through the Spring proxy
     *  rather than by self-invocation. */
    private void applyTransition(Certificate cert, CertificateState toState,
                                 @Nullable CertificateEvent auditEventOverride,
                                 @Nullable String reasonMessage) {
        Objects.requireNonNull(cert, "cert");
        Objects.requireNonNull(toState, "toState");
        CertificateState fromState = cert.getState();
        CertificateStateTransition row = CertificateStateTransition.lookup(fromState, toState)
            .orElseThrow(() -> new InvalidTransitionException(
                Resource.CERTIFICATE, cert.getUuid(), fromState, toState));

        cert.setState(toState);
        certificateRepository.save(cert);

        CertificateEvent auditEvent = auditEventOverride != null ? auditEventOverride : row.defaultAuditEvent;
        String message = reasonMessage != null
            ? reasonMessage
            : "State changed from %s to %s".formatted(fromState.getLabel(), toState.getLabel());
        // Status comes from the transition row: failure/rejection/failed-restore rows are audited
        // FAILED, not SUCCESS (the destination state alone can't tell them apart).
        eventHistoryService.addEventHistory(cert.getUuid(), auditEvent,
            row.defaultStatus, message, "");
    }
}
