package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.TimestampingWorkflowRequestDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class TimestampingWorkflowRequestDtoBuilder {

    private UUID signatureFormattingConnectorUuid = null;
    private List<RequestAttribute> signatureFormattingConnectorAttributes = new ArrayList<>();
    private Boolean qualifiedTimestamp = null;
    private UUID timeQualityConfigurationUuid = null;
    private String defaultPolicyId = null;
    private List<String> allowedPolicyIds = new ArrayList<>();
    private List<DigestAlgorithm> allowedDigestAlgorithms = new ArrayList<>();
    private Boolean validateTokenSignature = null;

    public static TimestampingWorkflowRequestDtoBuilder aTimestampingWorkflow() {
        return new TimestampingWorkflowRequestDtoBuilder();
    }

    public TimestampingWorkflowRequestDtoBuilder withSignatureFormattingConnector(UUID uuid) {
        this.signatureFormattingConnectorUuid = uuid;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withSignatureFormattingConnectorAttributes(List<RequestAttribute> attrs) {
        this.signatureFormattingConnectorAttributes = attrs;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withQualifiedTimestamp(boolean qualified) {
        this.qualifiedTimestamp = qualified;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withTimeQualityConfiguration(UUID uuid) {
        this.timeQualityConfigurationUuid = uuid;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withDefaultPolicyId(String oid) {
        this.defaultPolicyId = oid;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withAllowedPolicyIds(List<String> oids) {
        this.allowedPolicyIds = oids;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withAllowedDigestAlgorithms(List<DigestAlgorithm> algorithms) {
        this.allowedDigestAlgorithms = algorithms;
        return this;
    }

    public TimestampingWorkflowRequestDtoBuilder withValidateTokenSignature(boolean validate) {
        this.validateTokenSignature = validate;
        return this;
    }

    public TimestampingWorkflowRequestDto build() {
        TimestampingWorkflowRequestDto dto = new TimestampingWorkflowRequestDto();
        dto.setSignatureFormattingConnectorUuid(signatureFormattingConnectorUuid);
        dto.setSignatureFormattingConnectorAttributes(signatureFormattingConnectorAttributes);
        dto.setQualifiedTimestamp(qualifiedTimestamp);
        dto.setTimeQualityConfigurationUuid(timeQualityConfigurationUuid);
        dto.setDefaultPolicyId(defaultPolicyId);
        dto.setAllowedPolicyIds(allowedPolicyIds);
        dto.setAllowedDigestAlgorithms(allowedDigestAlgorithms);
        dto.setValidateTokenSignature(validateTokenSignature);
        return dto;
    }
}
