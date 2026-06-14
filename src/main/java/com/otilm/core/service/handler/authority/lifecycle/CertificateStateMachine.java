package com.otilm.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
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
 * <p>SM does NOT drive side effects (location cleanup, predecessor relations, dual-cert event
 * history) that v2's handleFailedOrRejectedEvent bundles. Caller remains responsible for those.</p>
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

    /** Default: SM resolves the audit event from the transition row's defaultAuditEvent. */
    @Transactional
    public void transition(Certificate cert, CertificateState toState) {
        transition(cert, toState, null, null);
    }

    /**
     * Runs in the caller's transaction (REQUIRED) so the state mutation and the audit-history
     * write commit atomically; the SM performs only local writes and no external calls.
     *
     * @param auditEventOverride if non-null, overrides the row's defaultAuditEvent
     * @param reasonMessage if non-null, used as the audit-history message; otherwise auto-generated
     */
    @Transactional
    public void transition(Certificate cert, CertificateState toState,
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
        eventHistoryService.addEventHistory(cert.getUuid(), auditEvent,
            CertificateEventStatus.SUCCESS, message, "");
    }
}
