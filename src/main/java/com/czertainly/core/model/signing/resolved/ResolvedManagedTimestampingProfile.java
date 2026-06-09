package com.czertainly.core.model.signing.resolved;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;

import java.util.List;
import java.util.UUID;

/**
 * Request-time resolved view of a managed timestamping Signing Profile.
 *
 * <p>Transient, per-request, and never cached.</p>
 *
 * @param uuid                                   Signing Profile UUID.
 * @param name                                   Signing Profile name.
 * @param description                            Optional description.
 * @param version                                Profile version.
 * @param enabled                                Whether the profile is enabled.
 * @param enabledProtocols                       Enabled protocols (e.g. TSP).
 * @param isQualifiedTimestamp                   ETSI qualified electronic timestamp flag.
 * @param defaultPolicyId                        Default TSA Policy ID.
 * @param allowedPolicyIds                       Accepted TSA Policy IDs.
 * @param allowedDigestAlgorithms                Accepted digest algorithms.
 * @param validateTokenSignature                 Whether to validate the token signature after issuance.
 * @param signatureFormatterConnectorAttributes  Attributes controlling DTBS construction.
 * @param timeQualityConfiguration               Resolved Time Quality Configuration (from TQC cache).
 * @param signatureFormatterConnector            Resolved Signature Formatter Connector routing info
 *                                               (from {@code CONNECTOR_API_CLIENT_CACHE}).
 * @param resolvedScheme                         Resolved scheme (e.g. resolved certificate).
 */
public record ResolvedManagedTimestampingProfile(
        UUID uuid,
        String name,
        String description,
        int version,
        boolean enabled,
        List<SigningProtocol> enabledProtocols,
        Boolean isQualifiedTimestamp,
        String defaultPolicyId,
        List<String> allowedPolicyIds,
        List<DigestAlgorithm> allowedDigestAlgorithms,
        Boolean validateTokenSignature,
        List<RequestAttribute> signatureFormatterConnectorAttributes,
        TimeQualityConfigurationModel timeQualityConfiguration,
        ApiClientConnectorInfo signatureFormatterConnector,
        ResolvedManagedScheme resolvedScheme
) implements ResolvedSigningProfile {

    @Override
    public SigningWorkflowType workflowType() {
        return SigningWorkflowType.TIMESTAMPING;
    }
}
