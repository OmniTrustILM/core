package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ContentSigningWorkflowRequestDtoBuilder {

    private UUID signatureFormattingConnectorUuid = null;
    private List<RequestAttribute> signatureFormattingConnectorAttributes = new ArrayList<>();

    public static ContentSigningWorkflowRequestDtoBuilder aContentSigningWorkflow() {
        return new ContentSigningWorkflowRequestDtoBuilder();
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormattingConnector(UUID uuid) {
        this.signatureFormattingConnectorUuid = uuid;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormattingConnectorAttributes(List<RequestAttribute> attrs) {
        this.signatureFormattingConnectorAttributes = attrs;
        return this;
    }

    public ContentSigningWorkflowRequestDto build() {
        ContentSigningWorkflowRequestDto dto = new ContentSigningWorkflowRequestDto();
        dto.setSignatureFormattingConnectorUuid(signatureFormattingConnectorUuid);
        dto.setSignatureFormattingConnectorAttributes(signatureFormattingConnectorAttributes);
        return dto;
    }
}
