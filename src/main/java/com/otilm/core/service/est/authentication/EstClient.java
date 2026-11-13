package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import java.util.UUID;

/**
 * An EST client as its authentication policy identified it. It holds no credential, so it can be logged and handed on.
 * Under {@link EstAuthenticationPolicy#CERTIFICATE_REGISTRATION} the client is identified by the registration it
 * completes, or by the one that its request already completed, and its password, the challenge of that registration, is
 * verified when the registration is completed; every other policy has verified the credential that the client
 * presented.
 *
 * @param policy the policy that identified the client
 * @param identity what the policy recognised the client by: {@code registration:<uuid>} for a pre-registered
 * certificate, {@code secret:<uuid>} for an RA credential, {@code certificate:<SHA-256 thumbprint>} for a client
 * certificate
 * @param registrationCertificateUuid the pre-registered certificate that the client completes; only under the
 * {@link EstAuthenticationPolicy#CERTIFICATE_REGISTRATION} policy, {@code null} otherwise
 */
public record EstClient(EstAuthenticationPolicy policy, String identity, UUID registrationCertificateUuid) {

    /**
     * @param policy the policy that accepted the client
     * @param thumbprint the SHA-256 thumbprint of the client certificate
     * @return the client, identified as {@code certificate:<thumbprint>}, that completes no registration
     */
    public static EstClient ofCertificate(EstAuthenticationPolicy policy, String thumbprint) {
        return new EstClient(policy, "certificate:" + thumbprint, null);
    }
}
