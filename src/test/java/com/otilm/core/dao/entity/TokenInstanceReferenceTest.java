package com.otilm.core.dao.entity;

import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TokenInstanceReferenceTest {

    @Test
    void setConnector_copiesConnectorUuidAndName() {
        // given
        Connector connector = aConnector();
        TokenInstanceReference tokenInstance = aTokenInstanceReference();

        // when
        tokenInstance.setConnector(connector);

        // then
        assertEquals(connector.getUuid(), tokenInstance.getConnectorUuid());
        assertEquals(connector.getName(), tokenInstance.getConnectorName());
    }

    @Test
    void mapToDto_doesNotExposeConnectorUuid_whenConnectorIsAbsent() {
        // given
        TokenInstanceReference tokenInstance = aTokenInstanceReference();

        // when
        var dto = tokenInstance.mapToDto();

        // then
        assertNull(dto.getConnectorUuid());
    }

    private static Connector aConnector() {
        String connectorName = "provider-v2";
        Connector connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        connector.setName(connectorName);
        return connector;
    }

    private static TokenInstanceReference aTokenInstanceReference() {
        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setUuid(UUID.randomUUID());
        tokenInstance.setName("token-without-connector");
        return tokenInstance;
    }
}
