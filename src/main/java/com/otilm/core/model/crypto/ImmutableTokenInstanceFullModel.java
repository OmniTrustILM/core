package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ImmutableTokenInstanceFullModel(UUID uuid, String tokenInstanceUuid, String name,
        TokenInstanceStatus status, String kind, UUID connectorUuid, String connectorName, UUID connectorInterfaceUuid,
        ImmutableConnectorInterface connectorInterface,
        Set<TokenProfileBasicModel> tokenProfiles) implements TokenInstanceFullModel {

    public static ImmutableTokenInstanceFullModel from(TokenInstanceReference value) {
        Objects.requireNonNull(value, "Token instance is required.");
        return new ImmutableTokenInstanceFullModel(value.getUuid(), value.getTokenInstanceUuid(), value.getName(),
                value.getStatus(), value.getKind(), value.getConnectorUuid(), value.getConnectorName(),
                value.getConnectorInterfaceUuid(),
                value.getConnectorInterface() == null
                        ? null
                        : ImmutableConnectorInterface.from(value.getConnectorInterface()),
                value
                        .getTokenProfiles()
                        .stream()
                        .map(ImmutableTokenProfileBasicModel::from)
                        .collect(Collectors.toSet()));
    }

    @Override
    public long tokenProfileCount() {
        return tokenProfiles.size();
    }
}
