package com.otilm.core.service.trust;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.core.provisioning.ProvisioningApplyResponseDTO;
import com.otilm.core.provisioning.ProvisioningApplyStatusDTO;
import com.otilm.core.provisioning.ProvisioningException;
import com.otilm.core.provisioning.TrustedCertificateProvisioningApiClient;
import com.otilm.core.provisioning.TrustedCertificateProvisioningDTO;
import com.otilm.core.provisioning.TrustedCertificateProvisioningRequestDTO;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

/**
 * Platform trust managed from ILM through the tenant API of saas-provisioning. Changes are stored deferred and deployed
 * by one {@link #apply()}.
 *
 * <p>
 * Provisioning's own state messages never leave this class: a record's message is text Core shaped.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "provisioning.trusted-certificates.enabled", havingValue = "true")
public class ProvisioningPlatformTrust implements PlatformTrustManager {

    static final String NO_STATE_MESSAGE = "Platform reports no state";
    static final String UNKNOWN_STATE_MESSAGE = "Platform reports a state ILM does not know";

    private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";

    private final TrustedCertificateProvisioningApiClient client;

    public ProvisioningPlatformTrust(TrustedCertificateProvisioningApiClient client) {
        this.client = client;
    }

    @Override
    public boolean isManaged() {
        return true;
    }

    @Override
    public TrustedCertificatePlatformSource source() {
        return TrustedCertificatePlatformSource.PROVISIONING;
    }

    @Override
    public List<PlatformBundleCertificateDto> bundle() {
        return List.of();
    }

    /**
     * Stores the certificate deferred. A conflict means provisioning holds it already, for example because the answer
     * to an earlier attempt was lost, so the stored record is adopted rather than reported as a failure.
     */
    @Override
    public PlatformRecord create(String pem) {
        byte[] content = pem.getBytes(StandardCharsets.US_ASCII);
        try {
            TrustedCertificateProvisioningDTO created = client
                    .createTrustedCertificate(new TrustedCertificateProvisioningRequestDTO(content), true);
            return toRecord(created);
        } catch (HttpClientErrorException.Conflict e) {
            String fingerprint = fingerprintOf(content);
            return list()
                    .stream()
                    .filter(platformRecord -> Objects.equals(fingerprint, platformRecord.fingerprintSha256()))
                    .findFirst()
                    .orElseThrow(() -> new ProvisioningException(
                            "Platform reports the certificate as stored but does not list it"));
        } catch (RestClientException e) {
            throw new ProvisioningException("Failed to store the certificate on the platform", e);
        }
    }

    @Override
    public void delete(String platformUuid) {
        try {
            client.deleteTrustedCertificate(platformUuid, true);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("Platform no longer holds trusted certificate {}", platformUuid);
        } catch (RestClientException e) {
            throw new ProvisioningException("Failed to remove the certificate from the platform", e);
        }
    }

    @Override
    public PlatformApplyResult apply() {
        try {
            ProvisioningApplyResponseDTO deployment = client.apply().getBody();
            return deployment == null
                    ? PlatformApplyResult.nothingToApply()
                    : PlatformApplyResult.deploying(deployment);
        } catch (HttpClientErrorException.NotFound e) {
            return PlatformApplyResult.notSupported();
        } catch (RestClientException e) {
            throw new ProvisioningException("Failed to apply platform trust", e);
        }
    }

    @Override
    public List<PlatformRecord> list() {
        try {
            return client.listTrustedCertificates().stream().map(ProvisioningPlatformTrust::toRecord).toList();
        } catch (RestClientException e) {
            throw new ProvisioningException("Failed to list platform trust", e);
        }
    }

    @Override
    public Optional<ProvisioningApplyStatusDTO> applyStatus() {
        try {
            return Optional.ofNullable(client.getApplyStatus());
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (RestClientException e) {
            throw new ProvisioningException("Failed to read the platform trust deployment", e);
        }
    }

    private static PlatformRecord toRecord(TrustedCertificateProvisioningDTO dto) {
        byte[] content = dto.certificateContent();
        String state = dto.state();
        if (state == null || state.isBlank()) {
            return new PlatformRecord(dto.uuid(), fingerprintOf(content), content,
                    TrustedCertificatePlatformState.UNKNOWN, NO_STATE_MESSAGE);
        }
        try {
            return new PlatformRecord(dto.uuid(), fingerprintOf(content), content,
                    TrustedCertificatePlatformState.findByCode(state), null);
        } catch (ValidationException e) {
            return new PlatformRecord(dto.uuid(), fingerprintOf(content), content,
                    TrustedCertificatePlatformState.UNKNOWN, UNKNOWN_STATE_MESSAGE);
        }
    }

    /**
     * The SHA-256 fingerprint of a certificate the platform returned as PEM or DER; {@code null} when the content is
     * absent or not a certificate, so the record matches no inventory certificate.
     */
    private static String fingerprintOf(byte[] content) {
        if (content == null) {
            return null;
        }
        try {
            String text = new String(content, StandardCharsets.US_ASCII);
            X509Certificate certificate = text.contains(PEM_HEADER)
                    ? CertificateUtil.parseCertificate(text)
                    : CertificateUtil.getX509Certificate(content);
            return CertificateUtil.getThumbprint(certificate);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            log.warn("Platform returned trusted certificate content that is not a certificate");
            return null;
        }
    }
}
