package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.core.model.signing.CertificatePurposeRequirements;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Content-signing workflow for ILM-managed signing.
 *
 * @param signatureFormattingConnectorUuid UUID of the Signature Formatting Provider.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction.
 * @param family Signature family this profile produces.
 * @param level Signature level at which the profile signs every document.
 * @param timestampSourceProfileUuid TIMESTAMPING Signing Profile that issues the embedded timestamps. Time quality is
 * gated on that profile's own configuration; a content-signing profile never names one directly.
 * @param certificatePurpose Per-profile constraints on what the signing certificate is for.
 * @param allowedRequestAttributes Names of the groups and ungrouped request attributes a signing request may set.
 */
public record ManagedContentSigningWorkflow(UUID signatureFormattingConnectorUuid,
        List<RequestAttribute> signatureFormattingConnectorAttributes, String family, SignatureLevel level,
        UUID timestampSourceProfileUuid, CertificatePurposeRequirements certificatePurpose,
        Set<String> allowedRequestAttributes) implements ContentSigningWorkflow {
}
