package com.otilm.core.model.signing.resolved;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import java.util.List;
import java.util.UUID;

/**
 * Request-time resolved view of a managed content-signing Signing Profile. Transient, per-request, and never cached.
 *
 * @param uuid Signing Profile UUID.
 * @param name Signing Profile name.
 * @param description Optional description.
 * @param version Profile version.
 * @param enabled Whether the profile is enabled.
 * @param enabledProtocols Enabled protocols.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction.
 * @param family Signature family this profile produces.
 * @param maxLevel Highest level a request may ask for.
 * @param timestampSourceProfileName Name of the TIMESTAMPING profile that issues embedded timestamps, or {@code null}
 * when {@code maxLevel} is {@code SIGNED}. Name-keyed because the in-process timestamp bridge resolves by profile name,
 * matching the profile-model cache.
 * @param documentSizeCap Largest document accepted for signing, in bytes, or {@code null} for no profile-level cap.
 * Carried here for the accepting protocol edge to enforce; not enforced by the engine itself.
 * @param timeQualityConfiguration Resolved Time Quality Configuration acceptance gates on.
 * @param signatureFormattingConnector Resolved Signature Formatting Provider routing info.
 * @param resolvedScheme Resolved scheme (e.g. resolved certificate).
 */
public record ResolvedManagedContentSigningProfile(UUID uuid, String name, String description, int version,
        boolean enabled, List<SigningProtocol> enabledProtocols,
        List<RequestAttribute> signatureFormattingConnectorAttributes, SignatureFamily family, SignatureLevel maxLevel,
        String timestampSourceProfileName, Long documentSizeCap, TimeQualityConfigurationModel timeQualityConfiguration,
        ApiClientConnectorInfo signatureFormattingConnector,
        ResolvedManagedScheme resolvedScheme) implements ResolvedSigningProfile {

    @Override
    public SigningWorkflowType workflowType() {
        return SigningWorkflowType.CONTENT_SIGNING;
    }
}
