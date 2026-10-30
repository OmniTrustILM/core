package com.otilm.core.util.builders;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Builds a token snapshot on a v2 cryptography connector that declares no features. Tests declare only the features
 * their scenario turns on.
 */
public final class TokenInstanceFullModelBuilder {

    private ImmutableConnectorInterface connectorInterface = cryptographyV2Declaring(List.of());

    public static TokenInstanceFullModelBuilder aTokenSnapshot() {
        return new TokenInstanceFullModelBuilder();
    }

    public TokenInstanceFullModelBuilder withConnectorFeatures(FeatureFlag... features) {
        this.connectorInterface = cryptographyV2Declaring(List.of(features));
        return this;
    }

    /** A token on a v1 connector, which has no connector interface. */
    public TokenInstanceFullModelBuilder withoutConnectorInterface() {
        this.connectorInterface = null;
        return this;
    }

    public ImmutableTokenInstanceFullModel build() {
        UUID connectorInterfaceUuid = connectorInterface == null ? null : connectorInterface.uuid();
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "connector", connectorInterfaceUuid,
                connectorInterface, Set.of());
    }

    private static ImmutableConnectorInterface cryptographyV2Declaring(List<FeatureFlag> features) {
        return new ImmutableConnectorInterface(UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", features);
    }
}
