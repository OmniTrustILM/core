package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import java.util.Objects;
import java.util.UUID;

public record ImmutableTokenInstanceBasicModel(UUID uuid, String tokenInstanceUuid, String name,
        TokenInstanceStatus status, String kind, UUID connectorUuid, String connectorName, UUID connectorInterfaceUuid,
        ConnectorInterface connectorInterfaceCode, String connectorInterfaceVersion,
        long tokenProfileCount) implements TokenInstanceBasicModel {

    public static ImmutableTokenInstanceBasicModel from(TokenInstanceReference value) {
        Objects.requireNonNull(value, "Token instance is required.");
        ConnectorInterfaceEntity iface = value.getConnectorInterface();
        return new ImmutableTokenInstanceBasicModel(value.getUuid(), value.getTokenInstanceUuid(), value.getName(),
                value.getStatus(), value.getKind(), value.getConnectorUuid(), value.getConnectorName(),
                value.getConnectorInterfaceUuid(), iface == null ? null : iface.getInterfaceCode(),
                iface == null ? null : iface.getVersion(), value.getTokenProfiles().size());
    }
}
