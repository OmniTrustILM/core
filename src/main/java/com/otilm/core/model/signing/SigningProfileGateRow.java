package com.otilm.core.model.signing;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;

/** The columns of a signing profile that decide whether it may serve a native signing operation. */
public record SigningProfileGateRow(String name, boolean ilmNativeEnabled, boolean enabled,
        SigningWorkflowType workflowType, SigningScheme signingScheme) {
}
