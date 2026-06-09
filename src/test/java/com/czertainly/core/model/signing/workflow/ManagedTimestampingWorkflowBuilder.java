package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;

import java.util.List;
import java.util.UUID;

public final class ManagedTimestampingWorkflowBuilder {

    private UUID signatureFormatterConnectorUuid = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private List<RequestAttribute> signatureFormatterConnectorAttributes = List.of();
    private Boolean isQualifiedTimestamp = false;
    private UUID timeQualityConfigurationUuid = null;
    private String defaultPolicyId = "1.2.3.4.5";
    private List<String> allowedPolicyIds = List.of();
    private List<DigestAlgorithm> allowedDigestAlgorithms = List.of();
    private Boolean validateTokenSignature = false;

    public static ManagedTimestampingWorkflowBuilder aManagedTimestampingWorkflow() {
        return new ManagedTimestampingWorkflowBuilder();
    }

    public static ManagedTimestampingWorkflow valid() {
        return aManagedTimestampingWorkflow().build();
    }

    public ManagedTimestampingWorkflowBuilder signatureFormatterConnectorUuid(UUID v) {
        this.signatureFormatterConnectorUuid = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder signatureFormatterConnectorAttributes(List<RequestAttribute> v) {
        this.signatureFormatterConnectorAttributes = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder isQualifiedTimestamp(Boolean v) {
        this.isQualifiedTimestamp = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder timeQualityConfigurationUuid(UUID v) {
        this.timeQualityConfigurationUuid = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder defaultPolicyId(String v) {
        this.defaultPolicyId = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder allowedPolicyIds(List<String> v) {
        this.allowedPolicyIds = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder allowedDigestAlgorithms(List<DigestAlgorithm> v) {
        this.allowedDigestAlgorithms = v;
        return this;
    }

    public ManagedTimestampingWorkflowBuilder validateTokenSignature(Boolean v) {
        this.validateTokenSignature = v;
        return this;
    }

    public ManagedTimestampingWorkflow build() {
        return new ManagedTimestampingWorkflow(
                signatureFormatterConnectorUuid,
                signatureFormatterConnectorAttributes,
                isQualifiedTimestamp,
                timeQualityConfigurationUuid,
                defaultPolicyId,
                allowedPolicyIds,
                allowedDigestAlgorithms,
                validateTokenSignature
        );
    }
}
