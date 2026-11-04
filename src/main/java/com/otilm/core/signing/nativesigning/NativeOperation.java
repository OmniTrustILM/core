package com.otilm.core.signing.nativesigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;

/**
 * Operations of the native signing API. Each is served by exactly one workflow type and signs only with keys ILM
 * manages.
 */
public enum NativeOperation {

    SIGN_HASH(SigningWorkflowType.RAW_SIGNING),
    SIGN_DOCUMENT(SigningWorkflowType.CONTENT_SIGNING);

    private final SigningWorkflowType servedWorkflow;

    NativeOperation(SigningWorkflowType servedWorkflow) {
        this.servedWorkflow = servedWorkflow;
    }

    public SigningWorkflowType servedWorkflow() {
        return servedWorkflow;
    }
}
