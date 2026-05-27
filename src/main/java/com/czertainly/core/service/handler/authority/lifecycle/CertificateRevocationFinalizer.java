package com.czertainly.core.service.handler.authority.lifecycle;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.service.CryptographicKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Shared revoke-completion logic used by both the operator-driven path
 * ({@code ClientOperationServiceImpl.manuallyConfirmRevoke}) and the async poll-driven path
 * ({@code CertificateStatusPollListener.applyTerminalTransition}). Extracted to remove the
 * copy-paste of "apply preserved revoke attributes → capture destroyKey → clear pending fields"
 * and the duplicated best-effort key destruction.
 *
 * <p>Stateless leaf collaborator — depends only on {@link AttributeEngine} and
 * {@link CryptographicKeyService}. Neither the service nor the listener calls the other; both
 * call this. The caller owns the surrounding locked transaction and the state-machine
 * transition (the audit event and reason differ between callers), then runs
 * {@link #destroyKeyIfRequested} after commit, outside the lock.</p>
 */
@Component
public class CertificateRevocationFinalizer {

    private static final Logger logger = LoggerFactory.getLogger(CertificateRevocationFinalizer.class);

    private final AttributeEngine attributeEngine;
    private final CryptographicKeyService keyService;

    public CertificateRevocationFinalizer(AttributeEngine attributeEngine, CryptographicKeyService keyService) {
        this.attributeEngine = attributeEngine;
        this.keyService = keyService;
    }

    /** Captured decision about whether to destroy the cert's key after the revoke commits. */
    public record KeyCleanup(boolean destroyKey, UUID keyUuid) {
        public static final KeyCleanup NONE = new KeyCleanup(false, null);
    }

    /**
     * In-transaction revoke finalization: re-apply the preserved revoke attributes (best-effort),
     * capture the operator's destroyKey decision, and clear the pending-revoke fields. The caller
     * must perform the state-machine transition itself (audit event/reason vary per caller) and
     * call {@link #destroyKeyIfRequested} after the transaction commits.
     */
    public KeyCleanup prepareRevokeFinalization(Certificate cert) {
        applyPreservedRevokeAttributes(cert);
        boolean destroyKey = Boolean.TRUE.equals(cert.getPendingRevokeDestroyKey());
        UUID keyUuid = cert.getKey() != null ? cert.getKeyUuid() : null;
        cert.setPendingRevokeDestroyKey(null);
        cert.setPendingRevokeAttributes(null);
        return new KeyCleanup(destroyKey, keyUuid);
    }

    /**
     * Re-apply the revoke-attributes captured when the cert entered PENDING_REVOKE so the cert
     * detail reflects the revocation parameters. Best-effort: a failure here does not block the
     * state transition (the connector revoke has already completed upstream).
     */
    public void applyPreservedRevokeAttributes(Certificate cert) {
        if (cert.getPendingRevokeAttributes() == null || cert.getPendingRevokeAttributes().isEmpty()) {
            return;
        }
        try {
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.CERTIFICATE, cert.getUuid())
                            .connector(cert.getRaProfile().getAuthorityInstanceReference().getConnectorUuid())
                            .operation(AttributeOperation.CERTIFICATE_REVOKE).build(),
                    cert.getPendingRevokeAttributes());
        } catch (Exception e) {
            logger.warn("Failed to apply preserved revoke attributes for cert {}: {}",
                    cert.getUuid(), e.getMessage(), e);
        }
    }

    /**
     * Best-effort key destruction — runs AFTER the revoke transaction commits, outside any lock,
     * since destroyKey is a slow connector HTTP call. A failure is logged and does not affect the
     * already-committed REVOKED state.
     */
    public void destroyKeyIfRequested(KeyCleanup cleanup, UUID certUuid) {
        if (cleanup == null || !cleanup.destroyKey() || cleanup.keyUuid() == null) {
            return;
        }
        try {
            keyService.destroyKey(List.of(cleanup.keyUuid().toString()));
        } catch (Exception e) {
            logger.warn("Failed to destroy key {} after revoke of cert {}: {}",
                    cleanup.keyUuid(), certUuid, e.getMessage(), e);
        }
    }
}
