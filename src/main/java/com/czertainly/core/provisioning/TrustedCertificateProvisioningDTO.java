package com.czertainly.core.provisioning;

import java.time.LocalDateTime;

/**
 * Response DTO for trusted certificate from provisioning service.
 *
 * @param uuid               UUID of the trusted certificate
 * @param certificateContent Raw certificate content serialized as Base64 String in JSON
 * @param issuer             Certificate issuer DN
 * @param san                Subject alternative names
 * @param serialNumber       Certificate serial number
 * @param subject            Certificate subject DN
 * @param thumbprint         Certificate thumbprint (fingerprint)
 * @param notBefore          Certificate validity start date
 * @param notAfter           Certificate expiration date
 */
public record TrustedCertificateProvisioningDTO(
        String uuid,
        byte[] certificateContent,
        String issuer,
        String san,
        String serialNumber,
        String subject,
        String thumbprint,
        LocalDateTime notBefore,
        LocalDateTime notAfter
) {
}
