package com.otilm.core.model.signing.workflow;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;

import java.util.List;
import java.util.UUID;

/**
 * Timestamping workflow for ILM-managed signing.
 *
 * @param signatureFormattingConnectorUuid       UUID of the Signature Formatting Provider that
 *                                              constructs the DTBS for Timestamping.
 * @param signatureFormattingConnectorAttributes Attributes controlling DTBS construction on the
 *                                              Signature Formatting Provider.
 * @param isQualifiedTimestamp                  ETSI qualified electronic timestamp flag.
 * @param timeQualityConfigurationUuid          UUID of the Time Quality Configuration validating
 *                                              clock accuracy at signing time; required when
 *                                              {@code isQualifiedTimestamp} is {@code true}
 *                                              (ETSI EN 319 421).
 * @param defaultPolicyId                       Default TSA Policy ID (OID format).
 * @param allowedPolicyIds                      Accepted TSA Policy IDs (OID format).
 * @param allowedDigestAlgorithms               Accepted digest algorithms; empty means all.
 * @param validateTokenSignature                Whether to validate the token signature after issuance.
 */
public record ManagedTimestampingWorkflow(
        UUID signatureFormattingConnectorUuid,
        List<RequestAttribute> signatureFormattingConnectorAttributes,
        Boolean isQualifiedTimestamp,
        UUID timeQualityConfigurationUuid,
        String defaultPolicyId,
        List<String> allowedPolicyIds,
        List<DigestAlgorithm> allowedDigestAlgorithms,
        Boolean validateTokenSignature
) implements TimestampingWorkflow {
}
