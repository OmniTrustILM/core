package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SignatureParameterPolicy;

import java.util.List;
import java.util.UUID;

/**
 * Content-signing workflow for ILM-managed signing.
 *
 * @param signatureFormattingConnectorUuid UUID of the Signature Formatting Provider.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction.
 * @param family Signature family this profile produces.
 * @param maxLevel Highest level a request may ask for.
 * @param timestampSourceProfileUuid TIMESTAMPING Signing Profile that issues the embedded timestamps. Time quality is
 * gated on that profile's own configuration; a content-signing profile never names one directly.
 * @param documentSizeCap Largest document accepted for signing, in bytes, or {@code null} for no profile-level cap.
 * @param certificatePurpose Per-profile constraints on what the signing certificate is for.
 * @param parameterPolicy Allowed request parameter groups and what applies where the request does not override
 * anything.
 */
public record ManagedContentSigningWorkflow(UUID signatureFormattingConnectorUuid,
        List<RequestAttribute> signatureFormattingConnectorAttributes, SignatureFamily family, SignatureLevel maxLevel,
        UUID timestampSourceProfileUuid, Long documentSizeCap, CertificatePurposeRequirements certificatePurpose,
        SignatureParameterPolicy parameterPolicy) implements ContentSigningWorkflow {
}
