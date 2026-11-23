package com.otilm.core.service.writer;

import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.core.dao.entity.TrustedCertificate;
import com.otilm.core.dao.entity.TrustedCertificateSync;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.TrustedCertificateRepository;
import com.otilm.core.dao.repository.TrustedCertificateSyncRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.handler.SubtreeRevalidation;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The only writer of trusted certificate rows and of the {@code trusted_ca} flag they derive.
 *
 * <p>
 * Methods use the default propagation ({@code REQUIRED}): they join an ambient transaction or open one. A change of the
 * validation purpose publishes the subtree revalidation inside that transaction, since its listener runs only after
 * commit. {@code trusted_ca} is written only for CA and self-signed certificates, the ones whose flag is not
 * {@code null}; trust rows imported for end-entity certificates leave it alone.
 */
@Service
@RequiredArgsConstructor
public class TrustedCertificateWriter {

    private final TrustedCertificateRepository trustedCertificateRepository;
    private final TrustedCertificateSyncRepository trustedCertificateSyncRepository;
    private final X509CertificateRepository x509CertificateRepository;
    private final SubtreeRevalidation subtreeRevalidation;

    @Transactional
    public TrustedCertificate insert(X509CertificateEntity certificate, boolean validation, boolean platform,
            TrustedCertificatePlatformState state) {
        OffsetDateTime now = OffsetDateTime.now();
        TrustedCertificate row = new TrustedCertificate();
        row.setCertificateUuid(certificate.getUuid());
        row.setValidation(validation);
        row.setPlatform(platform);
        row.setPlatformState(state);
        row.setCreatedAt(now);
        row.setUpdatedAt(now);
        TrustedCertificate saved = trustedCertificateRepository.saveAndFlush(row);
        writeTrustedCa(certificate.getUuid(), validation, validation);
        return saved;
    }

    /**
     * Replaces the purposes of a trust row. Dropping the platform purpose keeps the row with its removal pending until
     * the platform confirms it; the orchestrator calls this for a platform drop only where platform trust is managed,
     * and deletes the row otherwise.
     */
    @Transactional
    public void setPurposes(UUID trustUuid, boolean validation, boolean platform) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        boolean validationChanged = row.isValidation() != validation;
        if (row.isPlatform() && !platform) {
            row.setPlatformRemovalPending(true);
        }
        row.setValidation(validation);
        row.setPlatform(platform);
        row.setUpdatedAt(OffsetDateTime.now());
        trustedCertificateRepository.saveAndFlush(row);
        if (validationChanged) {
            writeTrustedCa(row.getCertificateUuid(), validation, true);
        }
    }

    @Transactional
    public void markRemovalPending(UUID trustUuid) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        boolean hadValidation = row.isValidation();
        row.setValidation(false);
        row.setPlatform(false);
        row.setPlatformRemovalPending(true);
        row.setUpdatedAt(OffsetDateTime.now());
        trustedCertificateRepository.saveAndFlush(row);
        writeTrustedCa(row.getCertificateUuid(), false, hadValidation);
    }

    @Transactional
    public void delete(UUID trustUuid) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        boolean hadValidation = row.isValidation();
        UUID certificateUuid = row.getCertificateUuid();
        trustedCertificateRepository.delete(row);
        trustedCertificateRepository.flush();
        writeTrustedCa(certificateUuid, false, hadValidation);
    }

    @Transactional
    public void recordPlatformUuid(UUID trustUuid, String platformUuid) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        row.setPlatformUuid(platformUuid);
        row.setUpdatedAt(OffsetDateTime.now());
        trustedCertificateRepository.save(row);
    }

    @Transactional
    public void recordObserved(UUID trustUuid, TrustedCertificatePlatformState state, String message,
            OffsetDateTime checkedAt) {
        trustedCertificateRepository.updateObserved(trustUuid, state, message, checkedAt);
    }

    /**
     * Records the outcome of a comparison with the platform. The migration inserts the single row; a schema built from
     * the entities has none, so a missing row is created.
     */
    @Transactional
    public void recordSync(boolean initialImportDone, OffsetDateTime lastSuccessfulCheckAt, String lastError) {
        TrustedCertificateSync sync = trustedCertificateSyncRepository
                .findById(TrustedCertificateSync.SINGLETON_UUID)
                .orElseGet(() -> {
                    TrustedCertificateSync created = new TrustedCertificateSync();
                    created.setUuid(TrustedCertificateSync.SINGLETON_UUID);
                    return created;
                });
        sync.setInitialImportDone(initialImportDone);
        sync.setLastSuccessfulCheckAt(lastSuccessfulCheckAt);
        sync.setLastError(lastError);
        trustedCertificateSyncRepository.save(sync);
    }

    /**
     * Writes {@code trusted_ca} for a CA or self-signed certificate and, when its validation trust changed, queues the
     * revalidation of its subtree. The certificate is read again after the update, which clears the persistence
     * context, so the revalidation sees it attached to this transaction.
     */
    private void writeTrustedCa(UUID certificateUuid, boolean trusted, boolean revalidate) {
        X509CertificateEntity certificate = x509CertificateRepository.findByUuid(certificateUuid).orElseThrow();
        if (certificate.getTrustedCa() == null) {
            return;
        }
        x509CertificateRepository.updateTrustedCa(certificateUuid, trusted);
        if (revalidate) {
            X509CertificateEntity updated = x509CertificateRepository.findByUuid(certificateUuid).orElseThrow();
            subtreeRevalidation.publishFor(updated);
        }
    }
}
