package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
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
     * @return what the request did: started a deployment, found nothing to deploy, or found no apply on the platform
     * @throws PlatformTrustNotManagedException when platform trust is not managed here
     */
    PlatformApplyResult apply();

    /**
     * Lists the certificates the platform holds, with their state.
     *
     * @throws com.otilm.core.provisioning.ProvisioningException when the request to the platform fails
     */
    List<PlatformRecord> list();

    /** The state of the last deployment {@link #apply()} started, empty when the platform reports none. */
    Optional<ProvisioningApplyStatusDTO> applyStatus();
}
