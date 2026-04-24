package com.czertainly.core.provisioning;

import jakarta.validation.constraints.NotBlank;

/**
 * Request for provisioning a new proxy.
 *
 * @param proxyCode unique proxy identifier
 */
public record ProxyProvisioningRequestDTO(
        @NotBlank
        String proxyCode
) {
}
