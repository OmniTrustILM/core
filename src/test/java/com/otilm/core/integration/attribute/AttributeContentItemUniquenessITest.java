package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.util.BaseSpringBootTest;
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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.awaitility.Awaitility.await;

/**
 * Each plaintext value of a definition is stored in one row, which the lookup by value relies on: with two rows every
 * later write of the value failed.
 */
class AttributeContentItemUniquenessITest extends BaseSpringBootTest {

    private static final String SHARED_VALUE = "shared-profile";

    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private CertificateHandler certificateHandler;
    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Test
    void registeringDiscoveredMetadataStoresTheDefinitionButNoValues() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);

        certificateHandler
                .updateMetadataDefinition(List.<MetadataAttribute>of(metadataAttribute("pillar", "Retail")),
                        connector.getUuid(), "discovery-connector");

        Assertions.assertEquals(1, attributeDefinitionRepository.count());
        Assertions.assertEquals(0, attributeContentItemRepository.count(), "values arrive with the import, mapped");
    }

    @Test
    void concurrentWritersOfANewValueShareOneRow() throws Exception {
        UUID definitionUuid = createAttribute("profile", AttributeContentType.STRING, ProtectionLevel.NONE);
        UUID first = newCertificate();
        UUID second = newCertificate();
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        CountDownLatch firstWrote = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);

        ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newFixedThreadPool(2));
        try {
            Future<?> firstWriter = executor.submit(() -> transaction.executeWithoutResult(status -> {
                write(first, definitionUuid, SHARED_VALUE);
                firstWrote.countDown();
                awaitRelease(releaseFirst);
            }));
            Assertions.assertTrue(firstWrote.await(30, TimeUnit.SECONDS), "the first writer stored the value");

            Future<?> secondWriter = executor
                    .submit(() -> transaction
                            .executeWithoutResult(status -> write(second, definitionUuid, SHARED_VALUE)));
            // The second writer cannot see the first one's uncommitted row. It must wait on it rather than insert a
            // second row beside it; without the unique constraint it never waits and finishes on its own.
            await()
                    .atMost(Duration.ofSeconds(30))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> secondWriter.isDone() || aWriterWaitsOnALock());
            releaseFirst.countDown();

            firstWriter.get(30, TimeUnit.SECONDS);
            secondWriter.get(30, TimeUnit.SECONDS);
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
        }

        Assertions.assertEquals(1, attributeContentItemRepository.count(), "both writers share one row");
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(first, "profile"));
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(second, "profile"));
    }

    @Test
    void aValueWrittenTwiceInSequenceKeepsOneRow() throws Exception {
        UUID definitionUuid = createAttribute("profile", AttributeContentType.STRING, ProtectionLevel.NONE);
        write(newCertificate(), definitionUuid, SHARED_VALUE);
        write(newCertificate(), definitionUuid, SHARED_VALUE);

        Assertions.assertEquals(1, attributeContentItemRepository.count());
    }

    /**
     * Connectors send v2 metadata without a reference. The row the native insert writes has to be found by the
     * entity-mapped lookup of the same value; if the two rendered it differently, every write would add a row.
     */
    @Test
    void aMetadataValueWithoutReferenceStoredTwiceKeepsOneRow() throws Exception {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);
        MetadataAttributeV2 metadata = metadataAttribute("pillar", "Retail");

        for (int i = 0; i < 2; i++) {
            attributeEngine
                    .updateMetadataAttributes(List.of(metadata),
                            ObjectAttributeContentInfo
                                    .builder(Resource.CERTIFICATE, newCertificate())
                                    .connector(connector.getUuid())
                                    .build());
        }

        Assertions.assertEquals(1, attributeContentItemRepository.count());
    }

    @Test
    void aValueTooLargeForAPlainIndexIsStoredOnce() throws Exception {
        UUID definitionUuid = createAttribute("note", AttributeContentType.TEXT, ProtectionLevel.NONE);
        String value = "x".repeat(10_000);

        for (int i = 0; i < 2; i++) {
            attributeEngine
                    .updateObjectCustomAttributeContent(Resource.CERTIFICATE, newCertificate(), definitionUuid, null,
                            List.of(new TextAttributeContentV3(value)));
        }

        Assertions.assertEquals(1, attributeContentItemRepository.count());
    }

    @Test
    void encryptedValuesStayOneRowPerObject() throws Exception {
        UUID definitionUuid = createAttribute("secretProfile", AttributeContentType.STRING, ProtectionLevel.ENCRYPTED);
        write(newCertificate(), definitionUuid, SHARED_VALUE);
        write(newCertificate(), definitionUuid, SHARED_VALUE);

        Assertions
                .assertEquals(2, attributeContentItemRepository.count(),
                        "encrypted values are never shared, so the constraint must not fold them");
    }

    /**
     * Encrypted values are stored once per object, so objects sharing a value used to decrypt into identical rows, the
     * same state concurrent writers produced; with the unique constraint the switch itself would fail instead.
     */
    @Test
    void turningEncryptionOffLeavesOneRowPerValue() throws Exception {
        CustomAttributeV3 attribute = customAttribute("secretProfile", AttributeContentType.STRING,
                ProtectionLevel.ENCRYPTED);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        UUID first = newCertificate();
        UUID second = newCertificate();
        write(first, definitionUuid, SHARED_VALUE);
        write(second, definitionUuid, SHARED_VALUE);
        Assertions.assertEquals(2, attributeContentItemRepository.count());

        attribute.getProperties().setProtectionLevel(ProtectionLevel.NONE);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE));

        Assertions.assertEquals(1, attributeContentItemRepository.count(), "rows decrypting alike fold onto one");
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(first, "secretProfile"));
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(second, "secretProfile"));
        // The write the duplicate rows used to break.
        UUID third = newCertificate();
        write(third, definitionUuid, SHARED_VALUE);
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(third, "secretProfile"));
    }

    private boolean aWriterWaitsOnALock() throws SQLException {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("""
                        SELECT count(*) FROM pg_stat_activity
                         WHERE wait_event_type = 'Lock' AND query ILIKE '%attribute_content_item%'
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

    UUID newCertificate() {
        return certificateRepository.save(new Certificate()).getUuid();
    }

    void write(UUID certificateUuid, UUID definitionUuid, String value) {
        try {
            attributeEngine
                    .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                            List.of(new StringAttributeContentV3(value)));
        } catch (NotFoundException | AttributeException e) {
            throw new IllegalStateException(e);
        }
    }

    List<String> storedValues(UUID certificateUuid, String attributeName) {
        return attributeEngine
                .getObjectCustomAttributesContent(Resource.CERTIFICATE, certificateUuid)
                .stream()
                .filter(attribute -> attributeName.equals(attribute.getName()))
                .flatMap(attribute -> ((ResponseAttributeV3) attribute).getContent().stream())
                .map(content -> String.valueOf(content.getData()))
                .toList();
    }

    static CustomAttributeV3 customAttribute(String name, AttributeContentType contentType,
            ProtectionLevel protectionLevel) {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setProtectionLevel(protectionLevel);
        attribute.setProperties(properties);
        return attribute;
    }

    UUID createAttribute(String name, AttributeContentType contentType, ProtectionLevel protectionLevel)
            throws AttributeException {
        return attributeEngine
                .updateCustomAttributeDefinition(customAttribute(name, contentType, protectionLevel),
                        List.of(Resource.CERTIFICATE))
                .getUuid();
    }

    static MetadataAttributeV2 metadataAttribute(String name, String value) {
        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid(UUID.randomUUID().toString());
        metadata.setName(name);
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        metadata.setContent(List.of(new StringAttributeContentV2(null, value)));
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        metadata.setProperties(properties);
        return metadata;
    }
}
