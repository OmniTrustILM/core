package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.*;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.*;
import com.otilm.api.model.client.signing.profile.workflow.*;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;

import java.util.List;
import java.util.UUID;

public class SigningProfileRequestDtoBuilder {

    private String name = "test-signing-profile";
    private String description = null;
    private SigningSchemeRequestDto signingScheme = null;
    private WorkflowRequestDto workflow = new RawSigningWorkflowRequestDto();
    private List<RequestAttribute> customAttributes = null;
    private SigningRecordPolicyRequestDto recordPolicy = null;

    public static SigningProfileRequestDtoBuilder aSigningProfileRequest() {
        return new SigningProfileRequestDtoBuilder();
    }

    public static SigningProfileRequestDtoBuilder aSigningProfileRequestFromExistingProfile(SigningProfileDto dto) {
        return new SigningProfileRequestDtoBuilder()
                .withName(dto.getName())
                .withDescription(dto.getDescription())
                .withScheme(schemeRequestFromDto(dto.getSigningScheme()))
                .withWorkflow(workflowRequestFromDto(dto.getWorkflow()))
                .withCustomAttributes(requestAttributesFromResponse(dto.getCustomAttributes()));
    }

    public SigningProfileRequestDtoBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public SigningProfileRequestDtoBuilder withDescription(String description) {
        this.description = description;
        return this;
    }

    public SigningProfileRequestDtoBuilder withScheme(SigningSchemeRequestDto scheme) {
        this.signingScheme = scheme;
        return this;
    }

    public SigningProfileRequestDtoBuilder withWorkflow(WorkflowRequestDto workflow) {
        this.workflow = workflow;
        return this;
    }

    public SigningProfileRequestDtoBuilder withCustomAttributes(List<RequestAttribute> attrs) {
        this.customAttributes = attrs;
        return this;
    }

    public SigningProfileRequestDtoBuilder withRecordPolicy(SigningRecordPolicyRequestDto recordPolicy) {
        this.recordPolicy = recordPolicy;
        return this;
    }

    public SigningProfileRequestDtoBuilder withDelegatedSigning(UUID connectorUuid) {
        DelegatedSigningRequestDto scheme = new DelegatedSigningRequestDto();
        scheme.setConnectorUuid(connectorUuid);
        return withScheme(scheme);
    }

    public SigningProfileRequestDtoBuilder withDelegatedSigning(String connectorUuid) {
        return withDelegatedSigning(UUID.fromString(connectorUuid));
    }

    public SigningProfileRequestDtoBuilder withStaticKeyManagedSigning(UUID certificateUuid) {
        return withStaticKeyManagedSigning(certificateUuid, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256);
    }

    public SigningProfileRequestDtoBuilder withStaticKeyManagedSigning(UUID certificateUuid, RsaSignatureScheme scheme, DigestAlgorithm digest) {
        return withStaticKeyManagedSigning(certificateUuid, RsaSignatureAttributesBuilder.rsaSignatureAttributes().withScheme(scheme).withDigest(digest).build());
    }

    public SigningProfileRequestDtoBuilder withStaticKeyManagedSigning(UUID certificateUuid, List<RequestAttribute> signingOperationAttributes) {
        StaticKeyManagedSigningRequestDto s = new StaticKeyManagedSigningRequestDto();
        s.setCertificateUuid(certificateUuid);
        s.setSigningOperationAttributes(signingOperationAttributes);
        return withScheme(s);
    }

    public SigningProfileRequestDtoBuilder withOneTimeKeyManagedSigning(UUID raProfileUuid, UUID csrTemplateUuid, UUID tokenProfileUuid) {
        OneTimeKeyManagedSigningRequestDto scheme = new OneTimeKeyManagedSigningRequestDto();
        scheme.setRaProfileUuid(raProfileUuid);
        scheme.setCsrTemplateUuid(csrTemplateUuid);
        scheme.setTokenProfileUuid(tokenProfileUuid);
        return withScheme(scheme);
    }

    public SigningProfileRequestDtoBuilder withRawSigning() {
        return withWorkflow(new RawSigningWorkflowRequestDto());
    }

    public SigningProfileRequestDtoBuilder withContentSigning(UUID signatureFormattingConnectorUuid) {
        ContentSigningWorkflowRequestDto contentSigningWorkflow = new ContentSigningWorkflowRequestDto();
        contentSigningWorkflow.setSignatureFormattingConnectorUuid(signatureFormattingConnectorUuid);
        return withWorkflow(contentSigningWorkflow);
    }

    public SigningProfileRequestDtoBuilder withContentSigning(ContentSigningWorkflowRequestDto workflow) {
        return withWorkflow(workflow);
    }

    public SigningProfileRequestDtoBuilder withTimestamping(UUID signatureFormattingConnectorUuid) {
        return withTimestamping(TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow().withSignatureFormattingConnector(signatureFormattingConnectorUuid).build());
    }

    public SigningProfileRequestDtoBuilder withTimestamping(TimestampingWorkflowRequestDto workflow) {
        return withWorkflow(workflow);
    }

    public SigningProfileRequestDto build() {
        SigningProfileRequestDto dto = new SigningProfileRequestDto();
        dto.setName(name);
        dto.setDescription(description);
        dto.setSigningScheme(signingScheme);
        dto.setWorkflow(workflow);
        dto.setCustomAttributes(customAttributes);
        dto.setRecordPolicy(recordPolicy);
        return dto;
    }

    private static SigningSchemeRequestDto schemeRequestFromDto(SigningSchemeDto scheme) {
        return switch (scheme) {
            case DelegatedSigningDto d -> {
                DelegatedSigningRequestDto req = new DelegatedSigningRequestDto();
                req.setConnectorUuid(UUID.fromString(d.getConnector().getUuid()));
                req.setAttributes(requestAttributesFromResponse(d.getAttributes()));
                yield req;
            }
            case StaticKeyManagedSigningDto s -> {
                StaticKeyManagedSigningRequestDto req = new StaticKeyManagedSigningRequestDto();
                req.setCertificateUuid(s.getCertificate().getUuid());
                req.setSigningOperationAttributes(requestAttributesFromResponse(s.getSigningOperationAttributes()));
                yield req;
            }
            case OneTimeKeyManagedSigningDto o -> {
                OneTimeKeyManagedSigningRequestDto req = new OneTimeKeyManagedSigningRequestDto();
                req.setRaProfileUuid(UUID.fromString(o.getRaProfile().getUuid()));
                req.setCsrTemplateUuid(UUID.fromString(o.getCsrTemplate().getUuid()));
                req.setTokenProfileUuid(UUID.fromString(o.getTokenProfile().getUuid()));
                yield req;
            }
            default -> throw new IllegalArgumentException("Unknown signing scheme type: " + scheme.getClass());
        };
    }

    private static WorkflowRequestDto workflowRequestFromDto(WorkflowDto workflow) {
        return switch (workflow) {
            case RawSigningWorkflowDto ignored -> new RawSigningWorkflowRequestDto();
            case ContentSigningWorkflowDto c -> {
                ContentSigningWorkflowRequestDto req = new ContentSigningWorkflowRequestDto();
                if (c.getSignatureFormattingConnector() != null) {
                    req.setSignatureFormattingConnectorUuid(UUID.fromString(c.getSignatureFormattingConnector().getUuid()));
                }
                req.setSignatureFormattingConnectorAttributes(requestAttributesFromResponse(c.getSignatureFormattingConnectorAttributes()));
                yield req;
            }
            case TimestampingWorkflowDto t -> {
                TimestampingWorkflowRequestDto req = new TimestampingWorkflowRequestDto();
                if (t.getSignatureFormattingConnector() != null) {
                    req.setSignatureFormattingConnectorUuid(UUID.fromString(t.getSignatureFormattingConnector().getUuid()));
                }
                req.setSignatureFormattingConnectorAttributes(requestAttributesFromResponse(t.getSignatureFormattingConnectorAttributes()));
                req.setQualifiedTimestamp(t.getQualifiedTimestamp());
                if (t.getTimeQualityConfiguration() != null) {
                    req.setTimeQualityConfigurationUuid(UUID.fromString(t.getTimeQualityConfiguration().getUuid()));
                }
                req.setDefaultPolicyId(t.getDefaultPolicyId());
                req.setAllowedPolicyIds(t.getAllowedPolicyIds());
                req.setAllowedDigestAlgorithms(t.getAllowedDigestAlgorithms());
                req.setValidateTokenSignature(t.getValidateTokenSignature());
                yield req;
            }
            default -> throw new IllegalArgumentException("Unknown workflow type: " + workflow.getClass());
        };
    }

    private static List<RequestAttribute> requestAttributesFromResponse(List<ResponseAttribute> attrs) {
        if (attrs == null)
            return null;
        return attrs.stream().map(SigningProfileRequestDtoBuilder::requestAttributeFromResponse).toList();
    }

    private static RequestAttribute requestAttributeFromResponse(ResponseAttribute attr) {
        if (attr instanceof ResponseAttributeV2 v2) {
            return new RequestAttributeV2(v2.getUuid(), v2.getName(), v2.getContentType(), v2.getContent());
        }
        if (attr instanceof ResponseAttributeV3 v3) {
            return new RequestAttributeV3(v3.getUuid(), v3.getName(), v3.getContentType(), v3.getContent());
        }
        throw new IllegalArgumentException("Unsupported ResponseAttribute type: " + attr.getClass());
    }
}
