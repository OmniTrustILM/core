package com.otilm.core.service.trust;

import com.otilm.core.provisioning.ProvisioningApplyResponseDTO;

/**
 * What a request to apply platform trust did. Nothing to apply and a platform that cannot apply on request differ: the
 * first leaves the rows' states as they are, the second means the platform reports no state for them.
 *
 * @param outcome what happened
 * @param deployment the deployment that started, present only when {@code outcome} is {@link Outcome#DEPLOYING}
 */
public record PlatformApplyResult(Outcome outcome, ProvisioningApplyResponseDTO deployment) {

    public enum Outcome {
        /** A deployment carrying the stored changes started. */
        DEPLOYING,
        /** The platform had no stored change to deploy. */
        NOTHING_TO_APPLY,
        /** The platform cannot apply on request, such as an older provisioning service without the apply endpoint. */
        NOT_SUPPORTED
    }

    public static PlatformApplyResult deploying(ProvisioningApplyResponseDTO deployment) {
        return new PlatformApplyResult(Outcome.DEPLOYING, deployment);
    }

    public static PlatformApplyResult nothingToApply() {
        return new PlatformApplyResult(Outcome.NOTHING_TO_APPLY, null);
    }

    public static PlatformApplyResult notSupported() {
        return new PlatformApplyResult(Outcome.NOT_SUPPORTED, null);
    }
}
