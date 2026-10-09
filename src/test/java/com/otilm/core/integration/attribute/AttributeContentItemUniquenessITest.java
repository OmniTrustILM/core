package com.otilm.core.integration.attribute;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CodeBlockAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProgrammingLanguageEnum;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.CodeBlockAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.serialization.AttributeContentJson;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import com.otilm.core.util.SqlCapture;
import jakarta.persistence.EntityManagerFactory;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Each plaintext value of a definition is stored in one row, which the lookup by value relies on: with two rows every
 * later write of the value fails.
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
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Test
    void registeringDiscoveredMetadataStoresPlaintextValuesAheadOfTheImport() {
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);
        MetadataAttributeV2 pillar = metadataAttribute("pillar", "Retail");
        MetadataAttributeV2 token = metadataAttribute("token", "secret");
        token.getProperties().setProtectionLevel(ProtectionLevel.ENCRYPTED);

        certificateHandler
                .updateMetadataDefinition(List.<MetadataAttribute>of(pillar, token), Map
                        .of(pillar.getUuid(),
                                Set
                                        .<AttributeContent>of(new StringAttributeContentV2(null, "Retail"),
                                                new StringAttributeContentV2(null, "Corporate")),
                                token.getUuid(),
                                Set.<AttributeContent>of(new StringAttributeContentV2(null, "secret"))),
                        connector.getUuid(), "discovery-connector");

        Assertions.assertEquals(2, attributeDefinitionRepository.count());
        // Committed before the parallel import, which then finds them instead of inserting and waiting on another
        // import's transaction. An encrypted value is left to the import, which stores it encrypted per object.
        Assertions.assertEquals(2, attributeContentItemRepository.count());
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

    /**
     * Two writes storing the same new values in opposite order must not deadlock. The competitor holds the value that
     * sorts first and then stores the other one; a write that took its values in list order would already hold that
     * other one while waiting on the first, and the two would wait on each other.
     */
    @Test
    void writersOfTheSameNewValuesInOppositeOrderDoNotDeadlock() throws Exception {
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(listAttribute("profiles"), List.of(Resource.CERTIFICATE))
                .getUuid();
        UUID certificateUuid = newCertificate();
        StringAttributeContentV3 sortsFirst = new StringAttributeContentV3("profile-a");
        StringAttributeContentV3 sortsSecond = new StringAttributeContentV3("profile-b");
        assertThat(AttributeContentJson.render(sortsFirst)).isLessThan(AttributeContentJson.render(sortsSecond));
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newSingleThreadExecutor());
        try (Connection competitor = dataSource.getConnection()) {
            competitor.setAutoCommit(false);
            insertValue(competitor, definitionUuid, sortsFirst);

            Future<?> writer = executor.submit(() -> transaction.executeWithoutResult(status -> {
                try {
                    attributeEngine
                            .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid,
                                    null, List.of(sortsSecond, sortsFirst));
                } catch (NotFoundException | AttributeException e) {
                    throw new IllegalStateException(e);
                }
            }));
            await()
                    .atMost(Duration.ofSeconds(30))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> writer.isDone() || aWriterWaitsOnALock());
            insertValue(competitor, definitionUuid, sortsSecond);
            competitor.commit();

            writer.get(30, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        Assertions.assertEquals(2, attributeContentItemRepository.count());
        Assertions
                .assertEquals(List.of("profile-b", "profile-a"), storedValues(certificateUuid, "profiles"),
                        "the object keeps the values in the order it was given them");
    }

    /**
     * The database stores an object value once whatever order its keys arrive in, so the order new values are stored in
     * cannot follow the keys' arrival order either: here it would put b first for one writer and second for the other.
     */
    @Test
    void writersOfAnObjectValueWithItsKeysInAnotherOrderDoNotDeadlock() throws Exception {
        CustomAttributeV3 attribute = customAttribute("layouts", AttributeContentType.OBJECT, ProtectionLevel.NONE);
        attribute.getProperties().setList(true);
        attribute.getProperties().setMultiSelect(true);
        attribute.getProperties().setExtensibleList(true);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        UUID certificateUuid = newCertificate();
        ObjectAttributeContentV3 a = new ObjectAttributeContentV3(orderedMap("a", 1, "z", 0));
        ObjectAttributeContentV3 aKeysReversed = new ObjectAttributeContentV3(orderedMap("z", 0, "a", 1));
        ObjectAttributeContentV3 b = new ObjectAttributeContentV3(orderedMap("a", 2, "z", 0));
        assertThat(AttributeContentJson.render(b)).isLessThan(AttributeContentJson.render(aKeysReversed));
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newSingleThreadExecutor());
        try (Connection competitor = dataSource.getConnection()) {
            competitor.setAutoCommit(false);
            insertValue(competitor, definitionUuid, a);

            Future<?> writer = executor.submit(() -> transaction.executeWithoutResult(status -> {
                try {
                    attributeEngine
                            .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid,
                                    null, List.of(b, aKeysReversed));
                } catch (NotFoundException | AttributeException e) {
                    throw new IllegalStateException(e);
                }
            }));
            await()
                    .atMost(Duration.ofSeconds(30))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> writer.isDone() || aWriterWaitsOnALock());
            insertValue(competitor, definitionUuid, b);
            competitor.commit();

            writer.get(30, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        Assertions.assertEquals(2, attributeContentItemRepository.count());
        Assertions.assertEquals(List.of("{a=2, z=0}", "{a=1, z=0}"), storedValues(certificateUuid, "layouts"));
    }

    @Test
    void writersOfNewValuesOfTwoAttributesInOppositeOrderDoNotDeadlock() throws Exception {
        Map<UUID, String> names = Map
                .of(createAttribute("region", AttributeContentType.STRING, ProtectionLevel.NONE), "region",
                        createAttribute("tier", AttributeContentType.STRING, ProtectionLevel.NONE), "tier");
        UUID sortsFirst = names.keySet().stream().sorted().toList().getFirst();
        UUID sortsSecond = names.keySet().stream().sorted().toList().getLast();
        StringAttributeContentV3 value = new StringAttributeContentV3(SHARED_VALUE);
        UUID certificateUuid = newCertificate();
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        ExecutorService executor = new DelegatingSecurityContextExecutorService(Executors.newSingleThreadExecutor());
        try (Connection competitor = dataSource.getConnection()) {
            competitor.setAutoCommit(false);
            insertValue(competitor, sortsFirst, value);

            Future<?> writer = executor.submit(() -> transaction.executeWithoutResult(status -> {
                try {
                    attributeEngine
                            .updateObjectCustomAttributesContent(Resource.CERTIFICATE, certificateUuid,
                                    List
                                            .of(new RequestAttributeV3(sortsSecond, names.get(sortsSecond),
                                                    AttributeContentType.STRING, List.of(value)),
                                                    new RequestAttributeV3(sortsFirst, names.get(sortsFirst),
                                                            AttributeContentType.STRING, List.of(value))),
                                    null);
                } catch (ValidationException | NotFoundException | AttributeException e) {
                    throw new IllegalStateException(e);
                }
            }));
            await()
                    .atMost(Duration.ofSeconds(30))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> writer.isDone() || aWriterWaitsOnALock());
            insertValue(competitor, sortsSecond, value);
            competitor.commit();

            writer.get(30, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        Assertions.assertEquals(2, attributeContentItemRepository.count());
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(certificateUuid, "region"));
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(certificateUuid, "tier"));
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
        // Random letters: an index entry is compressed first, and repeated characters would fit a plain index after
        // all.
        String value = new Random(1899)
                .ints(10_000, 'a', 'z' + 1)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        for (int i = 0; i < 2; i++) {
            attributeEngine
                    .updateObjectCustomAttributeContent(Resource.CERTIFICATE, newCertificate(), definitionUuid, null,
                            List.of(new TextAttributeContentV3(value)));
        }

        Assertions.assertEquals(1, attributeContentItemRepository.count());
    }

    /**
     * jsonb_hash_extended folds a container's start into its hash without rotating it, so two empty containers in a row
     * cancel out and these values hash alike. Keyed on that hash, the constraint would turn the second value away.
     */
    @Test
    void valuesAWeakHashConfusesAreStoredApart() throws Exception {
        UUID definitionUuid = createAttribute("layout", AttributeContentType.OBJECT, ProtectionLevel.NONE);
        UUID emptyObjects = newCertificate();
        UUID emptyArrays = newCertificate();

        writeObject(emptyObjects, definitionUuid, new HashMap<>(Map.of("v", List.of(Map.of(), Map.of()))));
        writeObject(emptyArrays, definitionUuid, new HashMap<>(Map.of("v", List.of(List.of(), List.of()))));

        Assertions.assertEquals(2, attributeContentItemRepository.count());
        Assertions.assertEquals(List.of("{v=[{}, {}]}"), storedValues(emptyObjects, "layout"));
        Assertions.assertEquals(List.of("{v=[[], []]}"), storedValues(emptyArrays, "layout"));
    }

    /**
     * The digest is taken from the value's jsonb text, which carries backslashes and characters outside ASCII; the
     * write and the lookup have to arrive at the same digest for them.
     */
    @Test
    void aValueWithBackslashesAndNonAsciiTextIsStoredOnce() throws Exception {
        UUID definitionUuid = createAttribute("profile", AttributeContentType.STRING, ProtectionLevel.NONE);
        String value = "C:\\pki\\\"root\" é 中";
        write(newCertificate(), definitionUuid, value);
        UUID second = newCertificate();
        write(second, definitionUuid, value);

        Assertions.assertEquals(1, attributeContentItemRepository.count());
        Assertions.assertEquals(List.of(value), storedValues(second, "profile"));
    }

    @Test
    void aStoredValueIsFoundThroughTheConstraintIndex() throws Exception {
        UUID definitionUuid = createAttribute("profile", AttributeContentType.STRING, ProtectionLevel.NONE);
        write(newCertificate(), definitionUuid, SHARED_VALUE);
        UUID certificateUuid = newCertificate();

        List<String> valueLookups = SqlCapture.during(() -> {
            write(certificateUuid, definitionUuid, SHARED_VALUE);
            return null;
        })
                .statements()
                .stream()
                .map(sql -> sql.toLowerCase().replaceAll("\\s+", ""))
                .filter(sql -> sql.startsWith("select") && sql.contains("attribute_content_item")
                        && (sql.contains("json=") || sql.contains("json_digest=")))
                .toList();

        assertThat(valueLookups).isNotEmpty().allMatch(sql -> sql.contains("json_digest="));
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
     * Encrypted values are stored once per object, so objects sharing a value decrypt to identical content; the switch
     * has to fold those rows onto one, or the unique constraint makes it fail.
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
        // A later write of the value resolves to the one remaining row.
        UUID third = newCertificate();
        write(third, definitionUuid, SHARED_VALUE);
        Assertions.assertEquals(List.of(SHARED_VALUE), storedValues(third, "secretProfile"));
    }

    /**
     * Turning encryption off on a widely used attribute must stay linear: a session holding every row of the definition
     * walks them all again on each statement the fold issues.
     */
    @Test
    void turningEncryptionOffLeavesTheRowsOutOfTheSession() throws Exception {
        CustomAttributeV3 attribute = customAttribute("secretProfile", AttributeContentType.STRING,
                ProtectionLevel.ENCRYPTED);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        List<UUID> certificates = new ArrayList<>();
        for (int i = 0; i < 120; i++) {
            UUID certificateUuid = newCertificate();
            certificates.add(certificateUuid);
            write(certificateUuid, definitionUuid, "value-" + (i % 2));
        }
        attribute.getProperties().setProtectionLevel(ProtectionLevel.NONE);

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        boolean statisticsWereEnabled = statistics.isStatisticsEnabled();
        statistics.setStatisticsEnabled(true);
        statistics.clear();
        try {
            attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE));

            Assertions
                    .assertEquals(0,
                            statistics.getEntityStatistics(AttributeContentItem.class.getName()).getLoadCount(),
                            "the switch reads rows as values, not as managed entities");
        } finally {
            statistics.setStatisticsEnabled(statisticsWereEnabled);
        }
        Assertions.assertEquals(2, attributeContentItemRepository.count());
        Assertions.assertEquals(List.of("value-0"), storedValues(certificates.getFirst(), "secretProfile"));
        Assertions.assertEquals(List.of("value-1"), storedValues(certificates.getLast(), "secretProfile"));
    }

    /**
     * Upload, issuance and protocol paths queue their own writes around an attribute write; storing a new value must
     * not flush them early.
     */
    @Test
    void storingANewValueLeavesUnrelatedPendingWritesQueued() throws Exception {
        UUID definitionUuid = createAttribute("profile", AttributeContentType.STRING, ProtectionLevel.NONE);
        UUID certificateUuid = newCertificate();

        List<String> statements = new TransactionTemplate(transactionManager).execute(status -> {
            Connector pending = new Connector();
            pending.setVersion(ConnectorVersion.V1);
            connectorRepository.save(pending);
            try {
                return SqlCapture.during(() -> {
                    write(certificateUuid, definitionUuid, SHARED_VALUE);
                    return null;
                }).statements();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });

        assertThat(statements).noneMatch(sql -> sql.toLowerCase().matches("(?s)insert into \\S*connector\\s*\\(.*"));
        Assertions.assertEquals(1, attributeContentItemRepository.count());
    }

    /**
     * Two switches of one definition visit its encrypted rows in the same order. In opposite orders each would hold a
     * row the other is about to fold into its own, and the two would wait on each other.
     */
    @Test
    void turningEncryptionOffVisitsTheEncryptedRowsInOneOrder() throws Exception {
        CustomAttributeV3 attribute = customAttribute("secretProfile", AttributeContentType.STRING,
                ProtectionLevel.ENCRYPTED);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        write(newCertificate(), definitionUuid, SHARED_VALUE);
        attribute.getProperties().setProtectionLevel(ProtectionLevel.NONE);

        List<String> statements = SqlCapture
                .during(() -> attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE)))
                .statements();

        List<String> encryptedRowReads = statements
                .stream()
                .map(sql -> sql.toLowerCase().replaceAll("\\s+", " "))
                .filter(sql -> sql.startsWith("select") && sql.contains("attribute_content_item")
                        && sql.contains("encrypted_data is not null"))
                .toList();
        assertThat(encryptedRowReads).isNotEmpty().allMatch(sql -> sql.contains("order by"));
    }

    /**
     * Each decrypted value is looked up through the unique index's key, and repeated mappings are dropped once per
     * surviving row: scanning every row of the definition per value, or a survivor's growing mappings per fold, makes
     * the switch quadratic.
     */
    @Test
    void turningEncryptionOffLooksValuesUpByTheirIndexedKey() throws Exception {
        CustomAttributeV3 attribute = customAttribute("secretProfile", AttributeContentType.STRING,
                ProtectionLevel.ENCRYPTED);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        for (int i = 0; i < 6; i++) {
            write(newCertificate(), definitionUuid, "value-" + (i % 2));
        }
        attribute.getProperties().setProtectionLevel(ProtectionLevel.NONE);

        List<String> statements = SqlCapture
                .during(() -> attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE)))
                .statements();

        List<String> valueLookups = statements
                .stream()
                .map(sql -> sql.toLowerCase().replaceAll("\\s+", ""))
                .filter(sql -> sql.startsWith("select") && sql.contains("attribute_content_item")
                        && (sql.contains("json=") || sql.contains("json_digest=")))
                .toList();
        assertThat(valueLookups).isNotEmpty().allMatch(sql -> sql.contains("json_digest="));
        long mappingDedupes = statements
                .stream()
                .map(String::toLowerCase)
                .filter(sql -> sql.startsWith("delete") && sql.contains("attribute_content_2_object")
                        && sql.contains("using"))
                .count();
        Assertions.assertEquals(2, mappingDedupes, "once per surviving value, not once per folded row");
        Assertions.assertEquals(2, attributeContentItemRepository.count());
    }

    /**
     * A row whose ciphertext decrypts to something the content type cannot parse comes back as its placeholder. Two
     * such placeholders are equal, so a lookup that reached encrypted rows would find both and fail the switch.
     */
    @Test
    void turningEncryptionOffGetsPastRowsWhoseValueCannotBeRead() throws Exception {
        CustomAttributeV3 attribute = customAttribute("secretScript", AttributeContentType.CODEBLOCK,
                ProtectionLevel.ENCRYPTED);
        UUID definitionUuid = attributeEngine
                .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE))
                .getUuid();
        for (String code : List.of("a", "b")) {
            attributeEngine
                    .updateObjectCustomAttributeContent(Resource.CERTIFICATE, newCertificate(), definitionUuid, null,
                            List
                                    .of(new CodeBlockAttributeContentV3(null,
                                            new CodeBlockAttributeContentData(ProgrammingLanguageEnum.PYTHON, code))));
        }
        new JdbcTemplate(dataSource)
                .update("UPDATE attribute_content_item SET encrypted_data = ?",
                        SecretsUtil.encryptAndEncodeSecretString("not-json", SecretEncodingVersion.V1));
        attribute.getProperties().setProtectionLevel(ProtectionLevel.NONE);

        Assertions
                .assertDoesNotThrow(() -> attributeEngine
                        .updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE)));
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

    private static void insertValue(Connection connection, UUID definitionUuid, AttributeContent content)
            throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement("""
                INSERT INTO attribute_content_item (uuid, attribute_definition_uuid, json)
                VALUES (?, ?, CAST(? AS jsonb))
                ON CONFLICT (attribute_definition_uuid, json_digest) DO NOTHING
                """)) {
            insert.setObject(1, UUID.randomUUID());
            insert.setObject(2, definitionUuid);
            insert.setString(3, AttributeContentJson.render(content));
            insert.executeUpdate();
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

    static LinkedHashMap<String, Object> orderedMap(String firstKey, Object firstValue, String secondKey,
            Object secondValue) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put(firstKey, firstValue);
        map.put(secondKey, secondValue);
        return map;
    }

    void writeObject(UUID certificateUuid, UUID definitionUuid, Serializable data) {
        try {
            attributeEngine
                    .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                            List.of(new ObjectAttributeContentV3(data)));
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

    static CustomAttributeV3 listAttribute(String name) {
        CustomAttributeV3 attribute = customAttribute(name, AttributeContentType.STRING, ProtectionLevel.NONE);
        attribute.getProperties().setList(true);
        attribute.getProperties().setMultiSelect(true);
        attribute.getProperties().setExtensibleList(true);
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
