package com.otilm.core.certificate.request;

/**
 * Validation policy for an externally supplied CSR, resolved from the RA Profile.
 *
 * @param strict    {@code true} rejects on any error; {@code false} downgrades errors to warnings.
 * @param whitelist {@code true} treats RDN/SAN/extension targets not in the resolved set as errors.
 */
public record RequestAttributePolicy(boolean strict, boolean whitelist) {

    public static RequestAttributePolicy lenient() {
        return new RequestAttributePolicy(false, false);
    }
}
