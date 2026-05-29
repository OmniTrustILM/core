package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.client.attribute.RequestAttribute;

import java.util.List;
import java.util.UUID;

/**
 * Content-signing workflow for ILM-managed signing.
 *
 * @param signatureFormatterConnectorUuid       UUID of the Signature Formatter Connector.
 * @param signatureFormatterConnectorAttributes Attributes controlling DTBS construction.
 */
public record ManagedContentSigningWorkflow(
        UUID signatureFormatterConnectorUuid,
        List<RequestAttribute> signatureFormatterConnectorAttributes
) implements ContentSigningWorkflow {
}
