package com.czertainly.core.model.signing.scheme;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;

import java.util.List;
import java.util.UUID;

/**
 * Scheme model for managed signing using a freshly issued one-time certificate and key pair.
 *
 * @param raProfileUuid               UUID of the RA Profile used to issue the one-time signing certificate.
 * @param tokenProfileUuid            UUID of the Token Profile used to store and manage the issued certificate and key pair.
 * @param csrTemplateUuid             UUID of the CSR Template used for the certificate issuance request.
 * @param signingOperationAttributes  Attributes required for signing operations (such as digest algorithm).
 */
public record OneTimeKeyManagedSigning(
        UUID raProfileUuid,
        UUID tokenProfileUuid,
        UUID csrTemplateUuid,
        List<RequestAttribute> signingOperationAttributes
) implements ManagedSigning {

    @Override
    public ManagedSigningType getManagedSigningType() {
        return ManagedSigningType.ONE_TIME_KEY;
    }
}
