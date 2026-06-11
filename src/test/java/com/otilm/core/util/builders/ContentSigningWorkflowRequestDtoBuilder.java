package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ContentSigningWorkflowRequestDtoBuilder {

    private UUID signatureFormatterConnectorUuid = null;
    private List<RequestAttribute> signatureFormatterConnectorAttributes = new ArrayList<>();

    public static ContentSigningWorkflowRequestDtoBuilder aContentSigningWorkflow() {
        return new ContentSigningWorkflowRequestDtoBuilder();
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormatterConnector(UUID uuid) {
        this.signatureFormatterConnectorUuid = uuid;
        return this;
    }

    public ContentSigningWorkflowRequestDtoBuilder withSignatureFormatterConnectorAttributes(List<RequestAttribute> attrs) {
        this.signatureFormatterConnectorAttributes = attrs;
        return this;
    }

    public ContentSigningWorkflowRequestDto build() {
        ContentSigningWorkflowRequestDto dto = new ContentSigningWorkflowRequestDto();
        dto.setSignatureFormatterConnectorUuid(signatureFormatterConnectorUuid);
        dto.setSignatureFormatterConnectorAttributes(signatureFormatterConnectorAttributes);
        return dto;
    }
}
