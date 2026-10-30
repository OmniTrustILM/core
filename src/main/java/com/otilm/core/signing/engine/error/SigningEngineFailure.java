package com.otilm.core.signing.engine.error;

/**
 * Workflow-agnostic failure taxonomy for the common Signing Engine. Each protocol edge maps these onto its own
 * currency.
 */
public enum SigningEngineFailure {

    /** The caller supplied something the profile or the contract does not permit. */
    INVALID_INPUT,

    /** The caller's data is structurally wrong. */
    MALFORMED_INPUT,

    /** The platform's own configuration is wrong. */
    MISCONFIGURED,

    /**
     * The platform's time reference is not trustworthy enough to stamp with, so the operation refuses rather than lies.
     */
    TIME_UNAVAILABLE,

    /** A connector was reached but did not deliver. */
    CONNECTOR_FAULT,

    /**
     * The signature would have covered something other than what was authorized. The data-to-be-signed binding check
     * records this separately so it can be alerted on as a security event.
     */
    BINDING_VIOLATION,

    /** The signing key or the cryptography provider failed to produce a signature. */
    SIGNER_FAULT,

    /** A named step of a multi-step run failed. */
    STEP_FAILED
}
