package com.otilm.core.service.writer;

import com.otilm.core.dao.repository.CertificateRepository;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Clears a certificate's pending-issue claim stamp while it is still in {@code PENDING_ISSUE}. Runs in its own
 * {@code REQUIRES_NEW} transaction, since the callers hold none after the connector call.
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
