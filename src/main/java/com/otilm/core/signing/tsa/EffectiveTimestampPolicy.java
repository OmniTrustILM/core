package com.otilm.core.signing.tsa;

import com.otilm.core.signing.tsa.messages.TspRequest;
import java.util.Optional;

/**
 * Picks the TSA policy a timestamp token is issued under.
 *
 * <p>
 * RFC 3161 makes {@code policy} mandatory in {@code TSTInfo} while {@code reqPolicy} is optional in the request, so the
 * client's choice applies when it made one and the profile's default applies otherwise. A profile that configures no
 * default can therefore only serve requests that name a policy themselves.
 */
public final class EffectiveTimestampPolicy {

    private EffectiveTimestampPolicy() {
    }

    /** The policy to stamp with, absent when neither the request nor the profile supplies one. */
    public static Optional<String> resolve(TspRequest request, String defaultPolicyId) {
        return usable(request.policy().orElse(null)).or(() -> usable(defaultPolicyId));
    }

    /** A blank policy ID names no policy, wherever it came from. */
    private static Optional<String> usable(String policyId) {
        return Optional.ofNullable(policyId).filter(candidate -> !candidate.isBlank());
    }
}
