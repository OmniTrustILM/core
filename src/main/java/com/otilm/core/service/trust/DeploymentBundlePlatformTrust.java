package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.core.config.TrustedCertificatesConfig;
import com.otilm.core.provisioning.ProvisioningApplyStatusDTO;
import com.otilm.core.util.CertificateUtil;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Platform trust set in the deployment configuration, the bundle Core parsed at startup. ILM shows it and cannot change
 * it; a change goes through the helm values or the Platform resource.
 */
@Component
@ConditionalOnProperty(name = "provisioning.trusted-certificates.enabled", havingValue = "false", matchIfMissing = true)
public class DeploymentBundlePlatformTrust implements PlatformTrustManager {

    static final String NOT_MANAGED_MESSAGE = "Platform trust is set in the deployment configuration";

    private final TrustedCertificatesConfig trustedCertificatesConfig;

    public DeploymentBundlePlatformTrust(TrustedCertificatesConfig trustedCertificatesConfig) {
        this.trustedCertificatesConfig = trustedCertificatesConfig;
    }

    @Override
    public boolean isManaged() {
        return false;
    }

    @Override
    public TrustedCertificatePlatformSource source() {
        return trustedCertificatesConfig.getTrustedCertificates().isEmpty()
                ? TrustedCertificatePlatformSource.NONE
                : TrustedCertificatePlatformSource.DEPLOYMENT;
    }

    /** The bundle's certificates; {@code expiring} is left for the caller, which knows the threshold. */
    @Override
    public List<PlatformBundleCertificateDto> bundle() {
        return trustedCertificatesConfig
                .getTrustedCertificates()
                .stream()
                .map(DeploymentBundlePlatformTrust::toBundleCertificate)
                .toList();
    }

    @Override
    public PlatformRecord create(String pem) {
        throw new PlatformTrustNotManagedException(NOT_MANAGED_MESSAGE);
    }

    @Override
    public void delete(String platformUuid) {
        throw new PlatformTrustNotManagedException(NOT_MANAGED_MESSAGE);
    }

    @Override
    public PlatformApplyResult apply() {
        throw new PlatformTrustNotManagedException(NOT_MANAGED_MESSAGE);
    }

    @Override
    public List<PlatformRecord> list() {
        return List.of();
    }

    @Override
    public Optional<ProvisioningApplyStatusDTO> applyStatus() {
        return Optional.empty();
    }

    private static PlatformBundleCertificateDto toBundleCertificate(X509Certificate certificate) {
        PlatformBundleCertificateDto dto = new PlatformBundleCertificateDto();
        dto.setSubject(certificate.getSubjectX500Principal().getName());
        dto.setIssuer(certificate.getIssuerX500Principal().getName());
        dto.setSerialNumber(certificate.getSerialNumber().toString(16));
        dto.setFingerprint(fingerprintOf(certificate));
        dto.setNotBefore(toUtc(certificate.getNotBefore()));
        dto.setNotAfter(toUtc(certificate.getNotAfter()));
        return dto;
    }

    private static String fingerprintOf(X509Certificate certificate) {
        try {
            return CertificateUtil.getThumbprint(certificate);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot compute the fingerprint of a parsed bundle certificate", e);
        }
    }

    private static LocalDateTime toUtc(Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZoneOffset.UTC);
    }
}
