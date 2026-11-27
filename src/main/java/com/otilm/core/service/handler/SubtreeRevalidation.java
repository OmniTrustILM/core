package com.otilm.core.service.handler;

import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.transaction.CertificateValidationEvent;
import com.otilm.core.settings.SettingsCache;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Queues revalidation of a CA and of the certificates below it, after the CA's trust changed.
 */
@Slf4j
@Component
public class SubtreeRevalidation {

    private final CertificateRepository certificateRepository;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final int certificateChainMaxDepth;

    public SubtreeRevalidation(CertificateRepository certificateRepository,
            ApplicationEventPublisher applicationEventPublisher,
            @Value("${certificate.chain.max-depth:20}") int certificateChainMaxDepth) {
        this.certificateRepository = certificateRepository;
        this.applicationEventPublisher = applicationEventPublisher;
        this.certificateChainMaxDepth = certificateChainMaxDepth;
    }

    /**
     * Publishes a {@link CertificateValidationEvent} for the CA and its descendants that are eligible for validation.
     *
     * <p>
     * The caller must hold a transaction: {@code CertificateHandler} handles the event only after commit and has no
     * fallback, so an event published outside a transaction is dropped. The CA must be attached to that transaction,
     * since the eligibility check reads its RA profile.
     *
     * @param ca the certificate authority whose trust changed
     */
    public void publishFor(Certificate ca) {
        boolean platformEnabled = SettingsCache
                .<PlatformSettingsDto>getSettings(SettingsSection.PLATFORM)
                .getCertificates()
                .getValidation()
                .getEnabled();
        List<UUID> toRevalidate = new ArrayList<>();
        if (isEligibleForRevalidation(ca, platformEnabled)) {
            toRevalidate.add(ca.getUuid());
        }
        toRevalidate
                .addAll(certificateRepository
                        .findAllDescendantCertificatesEligibleForValidation(ca.getUuid(), platformEnabled,
                                certificateChainMaxDepth));
        if (!toRevalidate.isEmpty()) {
            log
                    .debug("Publishing certificate validation event for CA subtree revalidation. caUuid={}, certificateCount={}",
                            ca.getUuid(), toRevalidate.size());
            applicationEventPublisher.publishEvent(new CertificateValidationEvent(toRevalidate));
        }
    }

    /**
     * Applies the same four eligibility rules to the CA node itself that
     * {@link CertificateRepository#findAllDescendantCertificatesEligibleForValidation} applies to its descendants in
     * SQL: not archived, certificate content present, validation status not REVOKED/EXPIRED, and RA-profile validation
     * flag (falling back to the platform flag when unset). Keep both in sync.
     */
    private static boolean isEligibleForRevalidation(Certificate certificate, boolean platformEnabled) {
        if (certificate.isArchived() || certificate.getCertificateContent() == null) {
            return false;
        }
        CertificateValidationStatus status = certificate.getValidationStatus();
        if (status == CertificateValidationStatus.REVOKED || status == CertificateValidationStatus.EXPIRED) {
            return false;
        }
        RaProfile raProfile = certificate.getRaProfile();
        Boolean rpEnabled = raProfile != null ? raProfile.getValidationEnabled() : null;
        return rpEnabled == null ? platformEnabled : rpEnabled;
    }
}
