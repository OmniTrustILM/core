package com.czertainly.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.czertainly.core.dao.entity.Certificate;

/**
 * v3-only capability: poll status and cancel in-flight async operations.
 */
public interface AsyncOperationCapability {

    StatusPollResult pollStatus(Certificate cert, CertificateOperation op) throws ConnectorException;

    CancelResult cancel(Certificate cert, CertificateOperation op) throws ConnectorException;
}
