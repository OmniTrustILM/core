package com.otilm.core.model.signing.scheme;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;

import java.util.List;
import java.util.UUID;

/**
 * Scheme model for managed signing using a pre-existing static certificate and key pair.
 *
 * @param certificateUuid              UUID of the certificate (and associated key) used for signing.
 * @param signingOperationAttributes   Attributes required for signing operations (such as digest algorithm).
 */
public record StaticKeyManagedSigning(
        UUID certificateUuid,
        List<RequestAttribute> signingOperationAttributes
) implements ManagedSigning {

    @Override
    public ManagedSigningType getManagedSigningType() {
        return ManagedSigningType.STATIC_KEY;
    }
}
