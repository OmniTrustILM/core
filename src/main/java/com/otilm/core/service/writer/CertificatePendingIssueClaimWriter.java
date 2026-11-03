package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.CertificateRepository;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Clears a certificate's pending-issue claim stamp once the authority has answered but the certificate stays in
 * {@code PENDING_ISSUE} (accepted asynchronously, or parked after a local failure). Runs in its own transaction: the
 * caller holds none after the connector call, and this write must not be able to roll back work the caller already
 * committed.
 */
@Component
public class CertificatePendingIssueClaimWriter {

    private final CertificateRepository certificateRepository;

    public CertificatePendingIssueClaimWriter(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /** @return the number of rows updated; 0 when the certificate is unknown or no longer in PENDING_ISSUE */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int clear(UUID certificateUuid) {
        return certificateRepository.clearPendingIssueClaim(certificateUuid);
    }
}
