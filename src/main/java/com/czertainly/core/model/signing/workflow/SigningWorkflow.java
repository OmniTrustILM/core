package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;

/**
 * Sealed interface for all signing-workflow-type-specific model objects.
 *
 * <p>Each workflow type is represented by a nested sealed interface that further splits into
 * scheme-specific record implementations ({@code Managed*} and {@code Delegated*}).
 * This ensures that fields valid only for managed signing (e.g. Signature Formatter Connector
 * references) are only accessible on the managed variant — enforced at compile time.</p>
 */
public sealed interface SigningWorkflow
        permits TimestampingWorkflow, ContentSigningWorkflow, RawSigningWorkflow {

    SigningWorkflowType getWorkflowType();
}
