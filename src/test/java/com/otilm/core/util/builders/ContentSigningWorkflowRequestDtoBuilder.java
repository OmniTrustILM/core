package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.TimestampSourceRequestDto;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ContentSigningWorkflowRequestDtoBuilder {

    private UUID signatureFormattingConnectorUuid = null;
    private List<RequestAttribute> signatureFormattingConnectorAttributes = new ArrayList<>();
    private SignatureFamily family = null;
    private SignatureLevel maxLevel = null;
    private TimestampSourceRequestDto timestampSource = null;
    private Long documentSizeCap = null;

    public static ContentSigningWorkflowRequestDtoBuilder aContentSigningWorkflow() {
        return new ContentSigningWorkflowRequestDtoBuilder();
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormattingConnector(UUID uuid) {
        this.signatureFormattingConnectorUuid = uuid;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormattingConnectorAttributes(
            List<RequestAttribute> attrs) {
        this.signatureFormattingConnectorAttributes = attrs;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withFamily(SignatureFamily family) {
        this.family = family;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withMaxLevel(SignatureLevel maxLevel) {
        this.maxLevel = maxLevel;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withInternalTimestampSource(UUID uuid) {
        this.timestampSource = new InternalTimestampSourceRequestDto(uuid);
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withDocumentSizeCap(Long documentSizeCap) {
        this.documentSizeCap = documentSizeCap;
        return this;
    }

    public ContentSigningWorkflowRequestDto build() {
        ContentSigningWorkflowRequestDto dto = new ContentSigningWorkflowRequestDto();
        dto.setSignatureFormattingConnectorUuid(signatureFormattingConnectorUuid);
        dto.setSignatureFormattingConnectorAttributes(signatureFormattingConnectorAttributes);
        dto.setFamily(family);
        dto.setMaxLevel(maxLevel);
        dto.setTimestampSource(timestampSource);
        dto.setDocumentSizeCap(documentSizeCap);
        return dto;
    }
}
