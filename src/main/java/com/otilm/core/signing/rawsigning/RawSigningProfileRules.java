package com.otilm.core.signing.rawsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningSchemeRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.signing.engine.signer.PrehashedSigning;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** The rules a signing profile is saved under because raw signing exists. */
public final class RawSigningProfileRules {

    private RawSigningProfileRules() {
    }

    /**
     * Only the static-key scheme resolves for raw signing, so a one-time-key raw profile would save cleanly and then
     * fail on every request.
     */
    public static void refuseOneTimeKey(SigningSchemeRequestDto scheme) {
        if (scheme instanceof OneTimeKeyManagedSigningRequestDto) {
            throw new ValidationException("Raw signing does not support the %s managed signing type"
                    .formatted(ManagedSigningType.ONE_TIME_KEY));
        }
    }

    /** A raw request carries a digest, so the key must sign under an algorithm that takes the digest as it is. */
    public static void requireDataDigestSigning(SignatureAlgorithm signatureAlgorithm) {
        if (!PrehashedSigning.admits(signatureAlgorithm)) {
            String code = signatureAlgorithm == null ? null : signatureAlgorithm.getCode();
            throw new ValidationException(
                    "Signature algorithm %s cannot sign a data digest, which raw signing requires".formatted(code));
        }
    }

    /**
     * The workflows whose profiles may not sign with the same key as a profile of the given workflow. A signature over
     * a raw digest is the same whichever certificate carries the key, so a raw caller could sign the digest of a
     * TSTInfo or of CMS signed attributes and forge what a timestamping or content-signing profile on that key attests.
     * Content signing and timestamping each sign only what they format themselves, so they may share a key.
     */
    public static Set<SigningWorkflowType> conflictingWorkflows(SigningWorkflowType workflowType) {
        return workflowType == SigningWorkflowType.RAW_SIGNING
                ? EnumSet.complementOf(EnumSet.of(SigningWorkflowType.RAW_SIGNING))
                : EnumSet.of(SigningWorkflowType.RAW_SIGNING);
    }

    /**
     * Refuses a key that profiles of a {@link #conflictingWorkflows conflicting workflow} already sign with.
     *
     * @param workflowType the workflow of the profile being saved
     * @param conflictingProfileNames the profiles of a conflicting workflow whose latest version signs with the key
     */
    public static void refuseSharedSigningKey(SigningWorkflowType workflowType, UUID certificateUuid,
            List<String> conflictingProfileNames) {
        if (conflictingProfileNames.isEmpty()) {
            return;
        }
        String profileNames = String.join(", ", conflictingProfileNames);
        String conflict = workflowType == SigningWorkflowType.RAW_SIGNING
                ? "The signing key of certificate %s also signs for Signing Profile(s) of another workflow: %s"
                        .formatted(certificateUuid, profileNames)
                : "The signing key of certificate %s signs raw digests for Signing Profile(s): %s"
                        .formatted(certificateUuid, profileNames);
        throw new ValidationException(conflict + ". A key that signs raw digests can serve no other workflow.");
    }
}
