package com.otilm.core.provisioning;

/**
 * The deployment a provisioning apply started.
 *
 * @param deploymentId identifier of the tenant deployment
 * @param configurationVersion version of the configuration the deployment carries
 */
public record ProvisioningApplyResponseDTO(long deploymentId, String configurationVersion) {
}
