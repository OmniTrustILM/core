package com.czertainly.core.model.signing.resolved;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;

/**
 * Sealed marker for the request-time resolved view of a Signing Profile.
 */
public sealed interface ResolvedSigningProfile
        permits ResolvedManagedTimestampingProfile {

    /** Workflow type for dispatch / logging. */
    SigningWorkflowType workflowType();
}
