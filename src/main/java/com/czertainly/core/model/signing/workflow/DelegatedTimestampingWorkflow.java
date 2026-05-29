package com.czertainly.core.model.signing.workflow;

import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;

import java.util.List;

/**
 * Timestamping workflow for delegated signing.
 *
 * <p>Contains only the common validation fields declared on {@link TimestampingWorkflow}.
 *
 * @param defaultPolicyId          Default TSA Policy ID (OID format).
 * @param allowedPolicyIds         Accepted TSA Policy IDs (OID format).
 * @param allowedDigestAlgorithms  Accepted digest algorithms; empty means all.
 * @param validateTokenSignature   Whether to validate the token signature after issuance.
 */
public record DelegatedTimestampingWorkflow(
        String defaultPolicyId,
        List<String> allowedPolicyIds,
        List<DigestAlgorithm> allowedDigestAlgorithms,
        Boolean validateTokenSignature
) implements TimestampingWorkflow {}
