package com.czertainly.core.model.signing.scheme;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;

import java.util.List;
import java.util.UUID;

/**
 * Scheme model for delegated signing.
 *
 * @param connectorUuid       UUID of the Connector used for delegated signing.
 * @param connectorAttributes Attributes provided by the delegated signing Connector.
 */
public record DelegatedSigning(
        UUID connectorUuid,
        List<RequestAttribute> connectorAttributes
) implements SigningSchemeModel {

    @Override
    public SigningScheme getSchemeType() {
        return SigningScheme.DELEGATED;
    }
}
