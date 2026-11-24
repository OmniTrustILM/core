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
        // Only a validation purpose writes the flag: a platform-only row never takes away validation trust.
        if (validation) {
            writeTrustedCa(certificate.getUuid(), true);
        }
        return saved;
    }

    /**
     * Brings the validation purpose of a certificate's trust row in line with a {@code trusted_ca} change the caller
     * has already made and published the revalidation for: adds a validation row, or drops the purpose and deletes a
     * row left without one. It never writes {@code trusted_ca} itself, so the caller's certificate stays attached.
     */
    @Transactional
    public void syncValidationPurpose(UUID certificateUuid, boolean validation) {
        TrustedCertificate row = trustedCertificateRepository.findByCertificateUuid(certificateUuid).orElse(null);
        if (validation) {
            if (row == null) {
                OffsetDateTime now = OffsetDateTime.now();
                TrustedCertificate created = new TrustedCertificate();
                created.setCertificateUuid(certificateUuid);
                created.setValidation(true);
                created.setCreatedAt(now);
                created.setUpdatedAt(now);
                trustedCertificateRepository.save(created);
            } else if (!row.isValidation()) {
                row.setValidation(true);
                row.setUpdatedAt(OffsetDateTime.now());
                trustedCertificateRepository.save(row);
            }
            return;
        }
        if (row == null || !row.isValidation()) {
            return;
        }
        if (row.isPlatform() || row.isPlatformRemovalPending()) {
            row.setValidation(false);
            row.setUpdatedAt(OffsetDateTime.now());
            trustedCertificateRepository.save(row);
        } else {
            trustedCertificateRepository.delete(row);
        }
    }

    /**
     * Replaces the purposes of a trust row. Dropping the platform purpose keeps the row with its removal pending until
     * the platform confirms it, and adding it back cancels that removal; the orchestrator calls this for a platform
     * drop only where platform trust is managed, and deletes the row otherwise.
     *
     * @throws IllegalArgumentException when no purpose would be left and no platform removal is pending; dropping the
     * last purpose is a removal
     */
    @Transactional
    public void setPurposes(UUID trustUuid, boolean validation, boolean platform) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        boolean removalPending = !platform && (row.isPlatform() || row.isPlatformRemovalPending());
        if (!validation && !platform && !removalPending) {
            throw new IllegalArgumentException("Trusted certificate %s would keep no purpose".formatted(trustUuid));
        }
        boolean validationChanged = row.isValidation() != validation;
        row.setValidation(validation);
        row.setPlatform(platform);
        row.setPlatformRemovalPending(removalPending);
        row.setUpdatedAt(OffsetDateTime.now());
        trustedCertificateRepository.saveAndFlush(row);
        if (validationChanged) {
            writeTrustedCa(row.getCertificateUuid(), validation);
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
        if (hadValidation) {
            writeTrustedCa(row.getCertificateUuid(), false);
        }
    }

    @Transactional
    public void delete(UUID trustUuid) {
        TrustedCertificate row = trustedCertificateRepository.findById(trustUuid).orElseThrow();
        boolean hadValidation = row.isValidation();
        UUID certificateUuid = row.getCertificateUuid();
        trustedCertificateRepository.delete(row);
        trustedCertificateRepository.flush();
        if (hadValidation) {
            writeTrustedCa(certificateUuid, false);
        }
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
     * Sets {@code trusted_ca} on a CA or self-signed certificate and, when the flag changes, queues the revalidation of
     * its subtree. The certificate is read again after the update, which clears the persistence context, so the
     * revalidation sees it attached to this transaction.
     */
    private void writeTrustedCa(UUID certificateUuid, boolean trusted) {
        X509CertificateEntity certificate = x509CertificateRepository.findByUuid(certificateUuid).orElseThrow();
        if (certificate.getTrustedCa() == null || certificate.getTrustedCa() == trusted) {
            return;
        }
        x509CertificateRepository.updateTrustedCa(certificateUuid, trusted);
        X509CertificateEntity updated = x509CertificateRepository.findByUuid(certificateUuid).orElseThrow();
        subtreeRevalidation.publishFor(updated);
    }
}
