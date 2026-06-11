package com.otilm.core.model.signing.resolved;

import com.otilm.core.signing.tsa.CertificateChain;

/**
 * Sealed interface for the resolved (request-time) representation of a managed signing scheme.
 *
 * <p>The resolved form is transient and intentionally embeds peer objects (entities or peer-cache models) — it is never cached.</p>
 *
 * <p>Only {@link ResolvedStaticKeyManagedSigning} is permitted today. The one-time-key variant is deferred.</p>
 */
public sealed interface ResolvedManagedScheme
        permits ResolvedStaticKeyManagedSigning {

    /**
     * The validated certificate chain to sign with and embed in the token, built once at resolution time.
     */
    CertificateChain chain();
}
