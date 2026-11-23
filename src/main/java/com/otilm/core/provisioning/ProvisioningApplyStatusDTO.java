package com.otilm.core.provisioning;

import java.time.OffsetDateTime;

/**
 * State of the last tenant deployment a provisioning apply started.
 *
 * @param deploymentId identifier of the tenant deployment
 * @param state deployment state as provisioning reports it
 * @param startedAt when the deployment started
 * @param finishedAt when the deployment finished, absent while it runs
 * @param error why the deployment failed, absent otherwise
 */
public record ProvisioningApplyStatusDTO(long deploymentId, String state, OffsetDateTime startedAt,
        OffsetDateTime finishedAt, String error) {
}
