package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TokenInstanceBasicModelTest {

    @Test
    void from_copiesInterfaceCodeAndVersion_fromLoadedInterface() {
        // given
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setUuid(UUID.randomUUID());
        iface.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        iface.setVersion("v2");
        TokenInstanceReference token = new TokenInstanceReference();
        token.setConnectorInterface(iface);

        // when
        ImmutableTokenInstanceBasicModel basic = ImmutableTokenInstanceBasicModel.from(token);
        ImmutableTokenInstanceFullModel full = ImmutableTokenInstanceFullModel.from(token);

        // then
        assertThat(basic.connectorInterfaceCode()).isEqualTo(ConnectorInterface.CRYPTOGRAPHY);
        assertThat(basic.connectorInterfaceVersion()).isEqualTo("v2");
        assertThat(full.connectorInterfaceCode()).isEqualTo(ConnectorInterface.CRYPTOGRAPHY);
        assertThat(full.connectorInterfaceVersion()).isEqualTo("v2");
    }

    @ParameterizedTest(name = "{0}, interface={1}")
    @MethodSource("tokenModels")
    void providerInterfaceVersion_matchesConnectorInterfacePresence(
            Function<TokenInstanceReference, TokenInstanceBasicModel> snapshotFactory, UUID interfaceUuid,
            int expectedVersion) {
        // given
        TokenInstanceReference token = new TokenInstanceReference();
        token.setConnectorInterfaceUuid(interfaceUuid);
        TokenInstanceBasicModel snapshot = snapshotFactory.apply(token);

        // when
        int version = snapshot.providerInterfaceVersion();

        // then
        assertThat(version).isEqualTo(expectedVersion);
    }

    private static Stream<Arguments> tokenModels() {
        Function<TokenInstanceReference, TokenInstanceBasicModel> basic = ImmutableTokenInstanceBasicModel::from;
        Function<TokenInstanceReference, TokenInstanceBasicModel> full = ImmutableTokenInstanceFullModel::from;
        UUID v2InterfaceUuid = UUID.randomUUID();
        int v1 = 1;
        int v2 = 2;
        return Stream
                .of(arguments(named("basic v1", basic), null, v1),
                        arguments(named("basic v2", basic), v2InterfaceUuid, v2),
                        arguments(named("full v1", full), null, v1),
                        arguments(named("full v2", full), v2InterfaceUuid, v2));
    }
}
