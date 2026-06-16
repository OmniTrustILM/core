package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.otilm.core.dao.entity.Certificate;

/**
 * v3-only capability: poll status and cancel in-flight async operations.
 */
public interface AsyncOperationCapability {

    /**
     * Polls the connector for the status of an async operation. The {@link StatusPollResult} carries
     * the operation status (in-progress / completed / failed); the caller maps it onto the certificate
     * state per the operation's transition matrix.
     */
    StatusPollResult pollStatus(Certificate cert, CertificateOperation op) throws ConnectorException;

    /**
     * Requests cancellation of an in-flight async operation. The {@link CancelResult}'s
     * {@link CancelOutcome} drives the caller's rollback decision: {@code CANCELLED} and
     * {@code NOT_TRACKED} are both soft successes — the operation is no longer running, so the caller
     * rolls local state back — while {@code REFUSED_PAST_POINT_OF_NO_RETURN} means the connector could
     * not cancel and local state must be left unchanged.
     */
    CancelResult cancel(Certificate cert, CertificateOperation op) throws ConnectorException;
}
