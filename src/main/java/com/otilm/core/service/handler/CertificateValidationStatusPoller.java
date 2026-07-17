package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Waits for a certificate's {@link CertificateValidationStatus} to leave
 * {@code NOT_CHECKED}. Shared by protocol handlers (CMP, SCEP) that must resolve a freshly
 * issued certificate's validation status before shaping their response, without reaching
 * into another protocol's package.
 */
@Slf4j
@Component
public class CertificateValidationStatusPoller {

    /**
     * Sampling interval for {@link #pollValidationStatus}. The event-driven post-issuance
     * validation typically lands ~100 ms after the certificate reaches ISSUED, so a
     * sub-second interval avoids routinely overshooting the wait.
     */
    private static final long POLL_INTERVAL_MS = 250L;

    @PersistenceContext
    private EntityManager entityManager;

    private CertificateInternalService certificateService;

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    /**
     * Wait for the certificate's {@link CertificateValidationStatus} to leave
     * {@code NOT_CHECKED}, up to {@code budgetMs}.
     *
     * <p>Validation is advanced asynchronously — event-driven on the validation-listener
     * thread right after issuance (typically ~100 ms after the certificate reaches ISSUED),
     * with the hourly batch as fallback. A response builder that reads {@code NOT_CHECKED}
     * should therefore wait briefly for the in-flight validation to land rather than
     * duplicating its OCSP/CRL work (and its status-changed events) with an inline
     * validation.</p>
     *
     * <p>Returns whatever status is current when the wait ends — {@code NOT_CHECKED} if the
     * budget was exhausted (or the thread was interrupted) without the validation landing;
     * the caller decides the fallback. The entity is fetched once and re-read via
     * {@link EntityManager#refresh} so the per-request authorization check on the fetch is
     * not repeated every sample.</p>
     *
     * @param uuid     internal UUID of the certificate
     * @param budgetMs maximum time to wait, in milliseconds
     * @return the certificate's validation status observed when the wait ended
     * @throws NotFoundException if no certificate exists for {@code uuid}
     */
    public CertificateValidationStatus pollValidationStatus(String uuid, long budgetMs) throws NotFoundException {
        Certificate certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(uuid));
        long start = System.currentTimeMillis();
        try {
            while (certificate.getValidationStatus() == CertificateValidationStatus.NOT_CHECKED
                    && System.currentTimeMillis() - start < budgetMs) {
                TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
                entityManager.refresh(certificate);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("UUID={} | validation-status wait interrupted; returning current status {}",
                    uuid, certificate.getValidationStatus());
        }
        return certificate.getValidationStatus();
    }
}
