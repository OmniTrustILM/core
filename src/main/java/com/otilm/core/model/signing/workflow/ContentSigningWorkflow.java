package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;

/**
 * Sealed interface for the {@code CONTENT_SIGNING} workflow model.
 *
 * <p>Content signing has no common fields shared between managed and delegated signing.
 */
public sealed interface ContentSigningWorkflow extends SigningWorkflow
        permits ManagedContentSigningWorkflow, DelegatedContentSigningWorkflow {

    @Override
    default SigningWorkflowType getWorkflowType() {
        return SigningWorkflowType.CONTENT_SIGNING;
    }
}
