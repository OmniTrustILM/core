package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * Two registrations of the same new attribute definition at once must leave one row and fail neither: with two rows,
 * every later lookup of the definition fails.
 */
class AttributeDefinitionUniquenessITest extends BaseSpringBootTest {

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DataSource dataSource;

    @FunctionalInterface
    interface Registration {
        void run() throws AttributeException;
    }

    @Test
    void concurrentFirstRegistrationsOfAConnectorsMetadataShareOneDefinition() throws Exception {
        UUID connector = newConnector();
        String name = "totalUrls-" + UUID.randomUUID();
        MetadataAttributeV2 metadata = metadataAttribute(UUID.randomUUID().toString(), name);

        race(() -> attributeEngine.updateMetadataAttributeDefinition(metadata, connector),
                () -> attributeEngine.updateMetadataAttributeDefinition(metadata, connector));

        assertThat(definitionsNamed(AttributeType.META, name)).hasSize(1);
    }

    @Test
    void concurrentFirstRegistrationsOfAGlobalNameUnderTwoUuidsShareOneDefinition() throws Exception {
        String name = "discoverySource-" + UUID.randomUUID();
        MetadataAttributeV2 first = globalMetadataAttribute(UUID.randomUUID().toString(), name);
        MetadataAttributeV2 second = globalMetadataAttribute(UUID.randomUUID().toString(), name);
        UUID firstConnector = newConnector();
        UUID secondConnector = newConnector();

        race(() -> attributeEngine.updateMetadataAttributeDefinition(first, firstConnector),
                () -> attributeEngine.updateMetadataAttributeDefinition(second, secondConnector));

        assertThat(definitionsNamed(AttributeType.META, name)).hasSize(1);
    }

    @Test
    void concurrentFirstRegistrationsOfAConnectorsDataAttributeShareOneDefinition() throws Exception {
        UUID connector = newConnector();
        String name = "port-" + UUID.randomUUID();
        DataAttributeV2 attribute = dataAttribute(UUID.randomUUID().toString(), name);

        race(() -> attributeEngine.updateDataAttributeDefinitions(connector, null, List.of(attribute)),
                () -> attributeEngine.updateDataAttributeDefinitions(connector, null, List.of(attribute)));

        assertThat(definitionsNamed(AttributeType.DATA, name)).hasSize(1);
    }

    @Test
    void concurrentFirstRegistrationsOfAGroupAttributeShareOneDefinition() throws Exception {
        UUID connector = newConnector();
        String name = "group-" + UUID.randomUUID();
        GroupAttributeV3 attribute = groupAttribute(UUID.randomUUID().toString(), name);

        race(() -> attributeEngine.updateDataAttributeDefinitions(connector, null, List.of(attribute)),
                () -> attributeEngine.updateDataAttributeDefinitions(connector, null, List.of(attribute)));

        assertThat(definitionsNamed(AttributeType.GROUP, name)).hasSize(1);
    }

    @Test
    void concurrentFirstRegistrationsOfAPlatformDataAttributeShareOneDefinition() throws Exception {
        String name = "platform-" + UUID.randomUUID();
        DataAttributeV2 attribute = dataAttribute(UUID.randomUUID().toString(), name);

        // Core registers its own data attributes, without a connector, on every start: two pods starting together.
        race(() -> attributeEngine.updateDataAttributeDefinitions(null, "platform-operation", List.of(attribute)),
                () -> attributeEngine.updateDataAttributeDefinitions(null, "platform-operation", List.of(attribute)));

        assertThat(definitionsNamed(AttributeType.DATA, name)).hasSize(1);
    }

    @Test
    void aFirstRegistrationGoesThroughTheConflictTolerantInsertAndARepeatWritesNothing() throws Exception {
        UUID connector = newConnector();
        MetadataAttributeV2 metadata = metadataAttribute(UUID.randomUUID().toString(), "roundTrip");

        List<String> first = SqlCapture
                .during(() -> attributeEngine.updateMetadataAttributeDefinition(metadata, connector))
                .statements();
        List<String> repeat = SqlCapture
                .during(() -> attributeEngine.updateMetadataAttributeDefinition(metadata, connector))
                .statements();

        assertThat(first)
                .anySatisfy(sql -> assertThat(sql.toLowerCase())
                        .contains("attribute_definition")
                        .contains("on conflict do nothing"))
                // The native insert's rendering reads back equal to the definition, so the first call's re-read
                // finds nothing to update; the repeat writes nothing either.
                .noneMatch(sql -> sql.toLowerCase().matches("(?s)update\\s+(\\w+\\.)?attribute_definition\\s.*"));
        assertThat(repeat)
                .noneMatch(sql -> sql.toLowerCase().contains("attribute_definition")
                        && (sql.toLowerCase().startsWith("insert") || sql.toLowerCase().startsWith("update")));
    }

    @Test
    void aDeletedConnectorsMetadataDoesNotBlockTheNextConnector() throws Exception {
        String name = "orphaned-" + UUID.randomUUID();
        MetadataAttributeV2 metadata = metadataAttribute(UUID.randomUUID().toString(), name);
        UUID first = newConnector();
        attributeEngine.updateMetadataAttributeDefinition(metadata, first);
        attributeEngine.deleteConnectorAttributeDefinitionsContent(first);
        UUID second = newConnector();
        attributeEngine.updateMetadataAttributeDefinition(metadata, second);
        attributeEngine.deleteConnectorAttributeDefinitionsContent(second);
        UUID third = newConnector();

        attributeEngine.updateMetadataAttributeDefinition(metadata, third);

        assertThat(definitionsNamed(AttributeType.META, name)).hasSize(3);
    }

    /**
     * A connector and its first definitions written in one transaction: the definition's insert runs natively, so the
     * connector still pending in the session has to land before it, or the connector foreign key refuses the row.
     */
    @Test
    void aConnectorAndItsFirstDefinitionStoreInOneTransaction() {
        String name = "sameTransaction-" + UUID.randomUUID();
        DataAttributeV2 attribute = dataAttribute(UUID.randomUUID().toString(), name);

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            Connector connector = new Connector();
            connector.setVersion(ConnectorVersion.V1);
            UUID connectorUuid = connectorRepository.save(connector).getUuid();
            register(() -> attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, List.of(attribute)));
        });

        assertThat(definitionsNamed(AttributeType.DATA, name)).hasSize(1);
    }

    @Test
    void aPlatformDataDefinitionReRegisteredWithAnotherContentTypeIsRefused() throws Exception {
        String uuid = UUID.randomUUID().toString();
        String name = "platform-" + UUID.randomUUID();
        attributeEngine.updateDataAttributeDefinitions(null, "platform-operation", List.of(dataAttribute(uuid, name)));
        DataAttributeV2 changed = dataAttribute(uuid, name);
        changed.setContentType(AttributeContentType.INTEGER);

        assertThatThrownBy(
                () -> attributeEngine.updateDataAttributeDefinitions(null, "platform-operation", List.of(changed)))
                .isInstanceOf(AttributeException.class);
    }

    /**
     * The first writer stores its definition and holds its transaction open; the second must wait on it rather than
     * insert a second row beside it. Without the unique keys the second never waits, and one of the two fails at
     * commit.
     */
    private void race(Registration firstWrite, Registration secondWrite) throws Exception {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        CountDownLatch firstWrote = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newFixedThreadPool(2));
        try {
            Future<?> first = executor.submit(() -> transaction.executeWithoutResult(status -> {
                register(firstWrite);
                firstWrote.countDown();
                awaitRelease(releaseFirst);
            }));
            assertThat(firstWrote.await(30, TimeUnit.SECONDS)).as("the first writer stored its definition").isTrue();

            Future<?> second = executor.submit(() -> transaction.executeWithoutResult(status -> register(secondWrite)));
            await()
                    .atMost(Duration.ofSeconds(30))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> second.isDone() || aWriterWaitsOnALock());
            releaseFirst.countDown();

            first.get(30, TimeUnit.SECONDS);
            second.get(30, TimeUnit.SECONDS);
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
        }
    }

    private static void register(Registration registration) {
        try {
            registration.run();
        } catch (AttributeException e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean aWriterWaitsOnALock() throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("""
                        SELECT count(*) FROM pg_stat_activity
                         WHERE wait_event_type = 'Lock' AND query ILIKE '%attribute_definition%'
                        """)) {
            rows.next();
            return rows.getLong(1) > 0;
        }
    }

    private static void awaitRelease(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("the test never released the first writer");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    List<AttributeDefinition> definitionsNamed(AttributeType type, String name) {
        return attributeDefinitionRepository
                .findAll()
                .stream()
                .filter(definition -> definition.getType() == type && name.equals(definition.getName()))
                .toList();
    }

    UUID newConnector() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        return connectorRepository.save(connector).getUuid();
    }

    static MetadataAttributeV2 metadataAttribute(String uuid, String name) {
        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid(uuid);
        metadata.setName(name);
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        metadata.setProperties(properties);
        return metadata;
    }

    static MetadataAttributeV2 globalMetadataAttribute(String uuid, String name) {
        MetadataAttributeV2 metadata = metadataAttribute(uuid, name);
        metadata.getProperties().setGlobal(true);
        return metadata;
    }

    static DataAttributeV2 dataAttribute(String uuid, String name) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        attribute.setProperties(properties);
        return attribute;
    }

    static GroupAttributeV3 groupAttribute(String uuid, String name) {
        GroupAttributeV3 attribute = new GroupAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/callback");
        callback.setCallbackMethod("GET");
        attribute.setAttributeCallback(callback);
        return attribute;
    }

    /**
     * Registrations order their definitions, so two that store the same new ones insert them in one order: the second
     * waits on the first instead of each holding what the other needs. The order shows in which definition a refused
     * list stores before it is refused, whatever order the connector listed them in.
     */
    @Test
    void definitionsWithCallbacksAreRegisteredInKeyOrder() throws Exception {
        UUID connector = newConnector();
        String name = "first-" + UUID.randomUUID();
        GroupAttributeV3 refused = groupAttribute("ffffffff-ffff-ffff-ffff-ffffffffffff", " ");
        GroupAttributeV3 accepted = groupAttribute("00000000-0000-0000-0000-00000000000a", name);

        assertThatThrownBy(
                () -> attributeEngine.updateAttributeDefinitionsWithCallback(connector, List.of(refused, accepted)))
                .isInstanceOf(AttributeException.class);

        assertThat(definitionsNamed(AttributeType.GROUP, name)).hasSize(1);
    }

    @Test
    void dataDefinitionsAreRegisteredInKeyOrder() throws Exception {
        UUID connector = newConnector();
        String name = "first-" + UUID.randomUUID();
        DataAttributeV2 refused = dataAttribute("ffffffff-ffff-ffff-ffff-ffffffffffff", " ");
        DataAttributeV2 accepted = dataAttribute("00000000-0000-0000-0000-00000000000a", name);

        assertThatThrownBy(
                () -> attributeEngine.updateDataAttributeDefinitions(connector, null, List.of(refused, accepted)))
                .isInstanceOf(AttributeException.class);

        assertThat(definitionsNamed(AttributeType.DATA, name)).hasSize(1);
    }
}
