package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.core.provisioning.ProvisioningApplyResponseDTO;
import com.otilm.core.provisioning.ProvisioningApplyStatusDTO;
import java.util.List;
import java.util.Optional;

/**
 * What the platform trusts, and, where ILM manages it, the way to change it. One implementation is active, chosen by
 * {@code provisioning.trusted-certificates.enabled}.
 */
public interface PlatformTrustManager {

    /** Whether ILM applies platform trust in this deployment. */
    boolean isManaged();

    TrustedCertificatePlatformSource source();

    /** The certificates of the deployment's read-only bundle; empty unless the source is the deployment. */
    List<PlatformBundleCertificateDto> bundle();

    /**
     * Stores a certificate on the platform without deploying it; {@link #apply()} deploys.
     *
     * @throws PlatformTrustNotManagedException when platform trust is not managed here
     */
    PlatformRecord create(String pem);

    /**
     * Removes a certificate from the platform without deploying the change; one the platform no longer knows counts as
     * removed.
     *
     * @throws PlatformTrustNotManagedException when platform trust is not managed here
     */
    void delete(String platformUuid);

    /**
     * Deploys the stored changes in one deployment.
     *
     * @return the deployment, or empty when there was nothing to deploy or the platform cannot apply on request
     * @throws PlatformTrustNotManagedException when platform trust is not managed here
     */
    Optional<ProvisioningApplyResponseDTO> apply();

    /**
     * Lists the certificates the platform holds, with their state.
     *
     * @throws com.otilm.core.provisioning.ProvisioningException when the platform cannot be reached
     */
    List<PlatformRecord> list();

    /** The state of the last deployment {@link #apply()} started, empty when the platform reports none. */
    Optional<ProvisioningApplyStatusDTO> applyStatus();
}
