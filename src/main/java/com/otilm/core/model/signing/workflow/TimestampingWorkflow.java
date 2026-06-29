package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;

import java.util.List;

/**
 * Sealed interface for the {@code TIMESTAMPING} workflow model.
 *
 * <p>Common validation fields ({@code defaultPolicyId}, {@code allowedPolicyIds},
 * {@code allowedDigestAlgorithms}, {@code validateTokenSignature}) are accessible on this
 * interface for both managed and delegated signing. Fields that are only relevant for
 * ILM-managed signing (Signature Formatting Provider reference, {@code isQualifiedTimestamp},
 * {@code timeQualityConfigurationUuid}) are scoped to {@link ManagedTimestampingWorkflow} only.</p>
 */
public sealed interface TimestampingWorkflow extends SigningWorkflow
        permits ManagedTimestampingWorkflow, DelegatedTimestampingWorkflow {

    @Override
    default SigningWorkflowType getWorkflowType() {
        return SigningWorkflowType.TIMESTAMPING;
    }

    String defaultPolicyId();
    List<String> allowedPolicyIds();
    List<DigestAlgorithm> allowedDigestAlgorithms();
    Boolean validateTokenSignature();
}
