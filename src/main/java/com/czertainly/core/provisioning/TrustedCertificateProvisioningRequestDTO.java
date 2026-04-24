package com.czertainly.core.provisioning;

import jakarta.validation.constraints.NotNull;

/**
 * Request for creating a new trusted certificate in provisioning service.
 *
 * @param certificateContent Raw certificate content serialized as Base64 String in JSON
 */
public record TrustedCertificateProvisioningRequestDTO(
        @NotNull
        byte[] certificateContent
) {
}
