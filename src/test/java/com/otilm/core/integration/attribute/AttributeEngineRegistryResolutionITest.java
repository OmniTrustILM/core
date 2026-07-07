package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

/**
 * #1622 N1/C6 — UUID-first resolution must return the row the caller referenced, and the legacy name-only
 * accessor must never 500 when two {@code operation=null} rows share a name. The two-row state is created via
 * the engine's own ingest path (registry/callback ingest writes {@code operation=null}).
 */
class AttributeEngineRegistryResolutionITest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private ConnectorRepository connectorRepository;

    private Connector connector;

    @BeforeEach
    void setUp() {
        connector = new Connector();
        connector.setName("c");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
    }

    private DataAttributeV2 dataAttr(UUID uuid, String name, AttributeContentType contentType) {
        DataAttributeV2 a = new DataAttributeV2();
        a.setUuid(uuid.toString());
        a.setName(name);
        a.setContentType(contentType);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("label");
        a.setProperties(props);
        return a;
    }

    @Test
    void twoOperationNullRowsDifferentUuid_strictAccessorReturnsReferencedUuidRow() throws AttributeException {
        UUID connectorUuid = connector.getUuid();
        UUID uuidA = UUID.randomUUID();
        UUID uuidB = UUID.randomUUID();
        String name = "shared";

        // Both ingests write operation=null (the registry/callback ingest path), manufacturing the C6 state.
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(uuidA, name, AttributeContentType.STRING)));
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(uuidB, name, AttributeContentType.INTEGER)));

        DataAttribute resolvedB = attributeEngine.getDataAttributeDefinitionStrict(connectorUuid, uuidB, name);
        Assertions.assertNotNull(resolvedB);
        Assertions.assertEquals(AttributeContentType.INTEGER, resolvedB.getContentType(), "must return the row whose attributeUuid == uuidB");
        Assertions.assertEquals(uuidB.toString(), resolvedB.getUuid());

        DataAttribute resolvedA = attributeEngine.getDataAttributeDefinitionStrict(connectorUuid, uuidA, name);
        Assertions.assertNotNull(resolvedA);
        Assertions.assertEquals(AttributeContentType.STRING, resolvedA.getContentType());
    }

    @Test
    void legacyNameOnlyAccessor_doesNotThrowOnDuplicateNames() throws AttributeException {
        UUID connectorUuid = connector.getUuid();
        String name = "shared";
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.STRING)));
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.INTEGER)));

        // The legacy Optional finder would throw IncorrectResultSizeDataAccessException here; the deterministic
        // list-finder route must return a row instead.
        DataAttribute resolved = Assertions.assertDoesNotThrow(() -> attributeEngine.getDataAttributeDefinition(connectorUuid, name));
        Assertions.assertNotNull(resolved);
    }

    @Test
    void strictAccessorWithNullName_returnsNull_doesNotThrow() {
        // A referenced uuid with a null name cannot match the (attributeUuid, name) key; must return null, not
        // NPE on List.of(null) (which would surface as a 500).
        Assertions.assertNull(Assertions.assertDoesNotThrow(
                () -> attributeEngine.getDataAttributeDefinitionStrict(connector.getUuid(), UUID.randomUUID(), null)));
    }

    @Test
    void strictAccessorWithNullUuid_degradesToNameOnly_doesNotThrow() throws AttributeException {
        // The NG retry path can call resolve(...) with a null attributeUuid (definition.getUuid() == null). The
        // strict accessor must degrade to deterministic name-only selection rather than NPE on List.of(null) (500).
        UUID connectorUuid = connector.getUuid();
        String name = "shared";
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.STRING)));
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.INTEGER)));

        DataAttribute resolved = Assertions.assertDoesNotThrow(
                () -> attributeEngine.getDataAttributeDefinitionStrict(connectorUuid, null, name));
        Assertions.assertNotNull(resolved);
    }

    @Test
    void legacyNameOnlyAccessor_tiebreakIsStableAcrossCalls() throws AttributeException {
        UUID connectorUuid = connector.getUuid();
        String name = "shared";
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.STRING)));
        attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(dataAttr(UUID.randomUUID(), name, AttributeContentType.INTEGER)));

        DataAttribute first = attributeEngine.getDataAttributeDefinition(connectorUuid, name);
        DataAttribute second = attributeEngine.getDataAttributeDefinition(connectorUuid, name);
        Assertions.assertEquals(first.getUuid(), second.getUuid(), "lexical-UUID tiebreak must be stable");
    }
}
