package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;

/**
 * Sealed interface for the {@code RAW_SIGNING} workflow model.
 */
public sealed interface RawSigningWorkflow extends SigningWorkflow
        permits ManagedRawSigningWorkflow, DelegatedRawSigningWorkflow {

    @Override
    default SigningWorkflowType getWorkflowType() {
        return SigningWorkflowType.RAW_SIGNING;
    }
}
