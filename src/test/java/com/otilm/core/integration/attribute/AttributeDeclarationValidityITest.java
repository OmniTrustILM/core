package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.auth.AttributeResource;
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
 * #1622 Task 4b — declaration-validity guard at the ingest choke point: dependsOn and callbackContext are
 * mutually exclusive, and dependsOn is forbidden on a RESOURCE-content attribute.
 */
class AttributeDeclarationValidityITest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private ConnectorRepository connectorRepository;

    private UUID connectorUuid;

    @BeforeEach
    void setUp() {
        Connector connector = new Connector();
        connector.setName("c");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
        connectorUuid = connector.getUuid();
    }

    private DataAttributeV2 base(AttributeContentType contentType) {
        DataAttributeV2 a = new DataAttributeV2();
        a.setUuid(UUID.randomUUID().toString());
        a.setName("attr");
        a.setContentType(contentType);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("label");
        if (contentType == AttributeContentType.RESOURCE) {
            props.setResource(AttributeResource.CERTIFICATE);
        }
        a.setProperties(props);
        return a;
    }

    @Test
    void dependsOnAndCallbackContextTogether_rejected() {
        DataAttributeV2 a = base(AttributeContentType.STRING);
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of("dep"));
        callback.setCallbackContext("/legacy");
        a.setAttributeCallback(callback);

        AttributeException ex = Assertions.assertThrows(AttributeException.class,
                () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(a)));
        Assertions.assertTrue(ex.getMessage().contains("dependsOn"));
    }

    @Test
    void dependsOnOnResourceContent_rejected() {
        DataAttributeV2 a = base(AttributeContentType.RESOURCE);
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of("dep"));
        a.setAttributeCallback(callback);

        Assertions.assertThrows(AttributeException.class,
                () -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(a)));
    }

    @Test
    void dependsOnOnly_ingestsCleanly() {
        DataAttributeV2 a = base(AttributeContentType.STRING);
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of("dep"));
        a.setAttributeCallback(callback);

        Assertions.assertDoesNotThrow(() -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(a)));
    }

    @Test
    void callbackContextOnly_ingestsCleanly() {
        DataAttributeV2 a = base(AttributeContentType.STRING);
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/legacy");
        a.setAttributeCallback(callback);

        Assertions.assertDoesNotThrow(() -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(a)));
    }

    @Test
    void noCallback_ingestsCleanly() {
        DataAttributeV2 a = base(AttributeContentType.STRING);
        Assertions.assertDoesNotThrow(() -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(a)));
    }
}
