package com.czertainly.core.model.signing.scheme;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;

/**
 * Sealed interface for all signing-scheme model objects.
 */
public sealed interface SigningSchemeModel
        permits ManagedSigning, DelegatedSigning {

    SigningScheme getSchemeType();
}
