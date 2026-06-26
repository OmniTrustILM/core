package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;

import java.util.List;
import java.util.UUID;

/**
 * Content-signing workflow for ILM-managed signing.
 *
 * @param signatureFormattingConnectorUuid       UUID of the Signature Formatting Provider.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction.
 */
public record ManagedContentSigningWorkflow(
        UUID signatureFormattingConnectorUuid,
        List<RequestAttribute> signatureFormattingConnectorAttributes
) implements ContentSigningWorkflow {
}
