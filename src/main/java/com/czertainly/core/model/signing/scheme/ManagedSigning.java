package com.czertainly.core.model.signing.scheme;

import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;

/**
 * Sealed interface for the managed-signing branch of the scheme model hierarchy.
 *
 * <p>Use pattern matching to access type-specific fields:</p>
 * <pre>{@code
 * switch (model.signingScheme()) {
 *     case StaticKeyManagedSigning s -> s.certificateUuid();
 *     case OneTimeKeyManagedSigning o -> o.raProfileUuid();
 * }
 * }</pre>
 */
public sealed interface ManagedSigning extends SigningSchemeModel
        permits StaticKeyManagedSigning, OneTimeKeyManagedSigning {

    @Override
    default SigningScheme getSchemeType() {
        return SigningScheme.MANAGED;
    }

    ManagedSigningType getManagedSigningType();
}
