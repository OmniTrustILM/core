package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;

import java.util.List;
import java.util.UUID;

/**
 * Content-signing workflow for ILM-managed signing.
 *
 * @param signatureFormattingConnectorUuid UUID of the Signature Formatting Provider.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction.
 * @param family Signature family this profile produces.
 * @param maxLevel Highest level a request may ask for.
 * @param timestampSourceProfileUuid TIMESTAMPING Signing Profile that issues the embedded timestamps.
 * @param documentSizeCap Largest document accepted for signing, in bytes, or {@code null} for no profile-level cap.
 * @param timeQualityConfigurationUuid Time Quality Configuration acceptance gates on, or {@code null} for the local
 * clock. Always {@code null} today: no field on a content-signing profile request populates it, so these profiles
 * resolve to the local clock until one does.
 */
public record ManagedContentSigningWorkflow(UUID signatureFormattingConnectorUuid,
        List<RequestAttribute> signatureFormattingConnectorAttributes, SignatureFamily family, SignatureLevel maxLevel,
        UUID timestampSourceProfileUuid, Long documentSizeCap,
        UUID timeQualityConfigurationUuid) implements ContentSigningWorkflow {
}
