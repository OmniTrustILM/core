package com.otilm.core.signing.rawsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningSchemeRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.service.handler.DataDigestSigningCapability.Support;
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
     * A provider that cannot sign a digest as it is would fail every raw request, so the profile is refused while its
     * operator is still setting it up. A token keeps the connector registration it was created on, so registering the
     * provider anew does not move an existing key: the profile needs a certificate of a key on such a registration.
     *
     * @param certificateUuid the signing certificate whose key the profile signs with
     * @param support whether the key's cryptography provider signs data digests
     */
    public static void requireDataDigestSigningProvider(UUID certificateUuid, Support support) {
        if (support == Support.SUPPORTED) {
            return;
        }
        String reason = support == Support.VERSION_1_PROVIDER
                ? "is registered as a version 1 connector"
                : "does not advertise data digest signing";
        throw new ValidationException(("The cryptography provider of the signing key of certificate %s %s, so it "
                + "cannot sign the data digests raw signing takes. Use a certificate whose key is on a cryptography "
                + "provider registered through a v2 connector that supports data digest signing.")
                .formatted(certificateUuid, reason));
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
     * Refuses a key that profiles of a {@link #conflictingWorkflows conflicting workflow} sign, or once signed, with.
     *
     * @param workflowType the workflow of the profile being saved
     * @param conflictingProfileNames the profiles of a conflicting workflow with a stored version on the key
     */
    public static void refuseSharedSigningKey(SigningWorkflowType workflowType, UUID certificateUuid,
            List<String> conflictingProfileNames) {
        if (conflictingProfileNames.isEmpty()) {
            return;
        }
        String profileNames = String.join(", ", conflictingProfileNames);
        String conflict = workflowType == SigningWorkflowType.RAW_SIGNING
                ? ("The signing key of certificate %s signs, or has signed, for Signing Profile(s) of another "
                        + "workflow: %s").formatted(certificateUuid, profileNames)
                : "The signing key of certificate %s signs, or has signed, raw digests for Signing Profile(s): %s"
                        .formatted(certificateUuid, profileNames);
        throw new ValidationException(conflict + ". A key that signs raw digests can serve no other workflow.");
    }
}
