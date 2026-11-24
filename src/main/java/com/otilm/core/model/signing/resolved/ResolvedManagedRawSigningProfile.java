package com.otilm.core.model.signing.resolved;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import java.util.List;
import java.util.UUID;

/**
 * Request-time resolved view of a managed raw-signing Signing Profile. Transient, per-request, and never cached.
 *
 * @param uuid Signing Profile UUID.
 * @param name Signing Profile name.
 * @param description Optional description.
 * @param version Profile version.
 * @param enabled Whether the profile is enabled.
 * @param enabledProtocols Enabled protocols.
 * @param certificatePurpose Per-profile constraints on what the signing certificate is for.
 * @param resolvedScheme Resolved scheme (e.g. resolved certificate).
 */
public record ResolvedManagedRawSigningProfile(UUID uuid, String name, String description, int version, boolean enabled,
        List<SigningProtocol> enabledProtocols, CertificatePurposeRequirements certificatePurpose,
        ResolvedManagedScheme resolvedScheme) implements ResolvedSigningProfile {

    @Override
    public SigningWorkflowType workflowType() {
        return SigningWorkflowType.RAW_SIGNING;
    }
}
