package com.otilm.core.signing.rawsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningSchemeRequestDto;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.signing.engine.signer.PrehashedSigning;
import java.util.List;
import java.util.UUID;

/**
 * What a raw signing profile cannot carry. Each rule is checked when the profile is saved, so a profile that could only
 * fail on every request is never stored.
 */
public final class RawSigningProfileRules {

    private RawSigningProfileRules() {
    }

    /** Only the static-key scheme resolves for raw signing. */
    public static void refuseOneTimeKey(SigningSchemeRequestDto scheme) {
        if (scheme instanceof OneTimeKeyManagedSigningRequestDto) {
            throw new ValidationException("Raw signing does not support the %s managed signing type"
                    .formatted(ManagedSigningType.ONE_TIME_KEY));
        }
    }

    /** A raw request carries a digest, so the key must sign under an algorithm that takes the digest as it is. */
    public static void requirePrehashedSigning(SignatureAlgorithm signatureAlgorithm) {
        if (!PrehashedSigning.admits(signatureAlgorithm)) {
            throw new ValidationException(
                    "Signature algorithm %s cannot sign a prehashed digest, which raw signing requires"
                            .formatted(signatureAlgorithm.getCode()));
        }
    }

    /**
     * A digest signed through a raw signing profile could forge what a profile of another workflow attests with the
     * same certificate, so a certificate that serves raw signing serves no other workflow.
     *
     * @param holderProfileNames the profiles of another workflow whose latest version signs with the certificate
     */
    public static void refuseCertificateHeldByAnotherWorkflow(UUID certificateUuid, List<String> holderProfileNames) {
        if (!holderProfileNames.isEmpty()) {
            throw new ValidationException(
                    "Certificate %s is used by Signing Profile(s) of another workflow, and a certificate that signs raw digests serves no other workflow: %s"
                            .formatted(certificateUuid, String.join(", ", holderProfileNames)));
        }
    }
}
