package com.otilm.core.integration.migration;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.DateAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateTimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TimeAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.serialization.AttributeContentJson;
import db.migration.V202610181200__RepairDateAttributeContent;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The stored values are written out literally, in the shapes the column mapper of releases before 2.20.0 left in the
 * database: generating them with today's Jackson would hide any change between the serializer that wrote them and the
 * deserializer that reads them back.
 */
class RepairDateAttributeContentMigrationITest extends BaseMigrationTest {

    private static final ZonedDateTime HALF_PAST_NINE = ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 0, ZoneOffset.UTC);

    @Autowired
    private DataSource dataSource;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;

    private final AtomicInteger placeholderSequence = new AtomicInteger();

    @Test
    void migrate_rewritesEachValueAsAWriteOfItStoresItToday() throws Exception {
        UUID dateDefinition = definition("validUntil", AttributeContentType.DATE, ProtectionLevel.NONE);
        UUID timeDefinition = definition("maintenanceAt", AttributeContentType.TIME, ProtectionLevel.NONE);
        UUID datetimeDefinition = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID dateCertificate = certificateHoldingStored(dateDefinition,
                "{\"reference\": \"ref-date\", \"data\": [2026, 3, 29], \"contentType\": \"date\"}");
        UUID wholeMinuteCertificate = certificateHoldingStored(timeDefinition,
                "{\"reference\": null, \"data\": [18, 0], \"contentType\": \"time\"}");
        UUID withSecondsCertificate = certificateHoldingStored(timeDefinition,
                "{\"reference\": \"ref-time\", \"data\": [18, 0, 5], \"contentType\": \"time\"}");
        UUID datetimeCertificate = certificateHoldingStored(datetimeDefinition,
                "{\"reference\": \"ref-datetime\", \"data\": 1768469400.123000000, \"contentType\": \"datetime\"}");
        UUID beforeTheEpochCertificate = certificateHoldingStored(datetimeDefinition,
                "{\"reference\": null, \"data\": -1.000000000, \"contentType\": \"datetime\"}");

        runMigration();

        assertRepaired(dateCertificate, dateDefinition,
                referenced(new DateAttributeContentV3(LocalDate.of(2026, 3, 29)), "ref-date"), "date");
        assertRepaired(wholeMinuteCertificate, timeDefinition, new TimeAttributeContentV3(LocalTime.of(18, 0)), "time");
        assertRepaired(withSecondsCertificate, timeDefinition,
                referenced(new TimeAttributeContentV3(LocalTime.of(18, 0, 5)), "ref-time"), "time");
        ZonedDateTime withMillis = HALF_PAST_NINE.plusNanos(123_000_000);
        assertRepaired(datetimeCertificate, datetimeDefinition,
                new DateTimeAttributeContentV3("ref-datetime", withMillis), "timestamptz");
        ZonedDateTime beforeTheEpoch = ZonedDateTime.of(1969, 12, 31, 23, 59, 59, 0, ZoneOffset.UTC);
        assertRepaired(beforeTheEpochCertificate, datetimeDefinition, new DateTimeAttributeContentV3(beforeTheEpoch),
                "timestamptz");

        assertThat(storedDatetime(datetimeCertificate, "reviewedAt"))
                .as("the number held the instant, which comes back in UTC")
                .isEqualTo(withMillis);
        assertThat(storedDatetime(beforeTheEpochCertificate, "reviewedAt")).isEqualTo(beforeTheEpoch);
    }

    /**
     * The migration selects by content type alone, so a definition a connector owns is repaired like a custom one. Its
     * version 2 rows were broken only where 2.19 and earlier decrypted them, when the definition's encryption was
     * turned off, and they carry no content type of their own.
     */
    @Test
    void migrate_repairsDefinitionsAConnectorOwns() throws Exception {
        UUID metadataDefinition = definition("notAfter", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID metadataCertificate = certificateHoldingStored(metadataDefinition,
                "{\"reference\": null, \"data\": 1768469400.000000000, \"contentType\": \"datetime\"}");
        UUID dataDateDefinition = definition("issuedOn", AttributeContentType.DATE, ProtectionLevel.NONE);
        UUID dataDateCertificate = certificateHoldingStored(dataDateDefinition,
                "{\"reference\": null, \"data\": [2026, 3, 29], \"contentType\": null}");
        UUID dataDatetimeDefinition = definition("issuedAfter", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID dataDatetimeCertificate = certificateHoldingStored(dataDatetimeDefinition,
                "{\"reference\": \"ref-issued\", \"data\": 1768469400.000000000, \"contentType\": null}");
        ownedByConnector(metadataDefinition, AttributeType.META, 3);
        ownedByConnector(dataDateDefinition, AttributeType.DATA, 2);
        ownedByConnector(dataDatetimeDefinition, AttributeType.DATA, 2);

        runMigration();

        assertRepaired(metadataCertificate, metadataDefinition, new DateTimeAttributeContentV3(HALF_PAST_NINE),
                "timestamptz");
        assertRepaired(dataDateCertificate, dataDateDefinition,
                new BaseAttributeContentV2<>(null, LocalDate.of(2026, 3, 29)), "date");
        assertRepaired(dataDatetimeCertificate, dataDatetimeDefinition,
                new BaseAttributeContentV2<>("ref-issued", HALF_PAST_NINE), "timestamptz");
    }

    @Test
    void migrate_foldsARepairedValueIntoTheRowAWriteAfterTheUpgradeStoredForIt() throws Exception {
        UUID definitionUuid = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID beforeUpgrade = certificateHoldingStored(definitionUuid,
                "{\"reference\": null, \"data\": 1768469400.000000000, \"contentType\": \"datetime\"}");
        UUID brokenItem = itemOf(beforeUpgrade, definitionUuid);
        UUID afterUpgrade = certificateWriting(definitionUuid, new DateTimeAttributeContentV3(HALF_PAST_NINE));
        UUID textItem = itemOf(afterUpgrade, definitionUuid);
        assertThat(textItem)
                .as("the lookup by value misses the broken row, so the write stored a second one")
                .isNotEqualTo(brokenItem);
        // An object mapped to both copies must hold the value once after the fold.
        mapAlso(afterUpgrade, brokenItem);

        runMigration();

        assertThat(storedJsonOrNull(brokenItem)).as("the broken row folds into the one holding its value").isNull();
        assertThat(itemOf(beforeUpgrade, definitionUuid)).isEqualTo(textItem);
        assertThat(mappingCount(afterUpgrade, textItem)).isEqualTo(1);
        assertThat(storedDatetime(beforeUpgrade, "reviewedAt")).isEqualTo(HALF_PAST_NINE);
        assertThat(storedDatetime(afterUpgrade, "reviewedAt")).isEqualTo(HALF_PAST_NINE);
    }

    @Test
    void migrate_foldsBrokenRowsThatRepairToTheSameValueIntoOne() throws Exception {
        UUID definitionUuid = definition("maintenanceAt", AttributeContentType.TIME, ProtectionLevel.NONE);
        UUID first = certificateHoldingStored(definitionUuid,
                "{\"reference\": null, \"data\": [18, 0], \"contentType\": \"time\"}");
        // The same time with its zero seconds written out: a second row, which jsonb keeps apart from the first.
        UUID second = certificateHoldingStored(definitionUuid,
                "{\"reference\": null, \"data\": [18, 0, 0], \"contentType\": \"time\"}");

        runMigration();

        assertThat(itemOf(first, definitionUuid)).isEqualTo(itemOf(second, definitionUuid));
        assertRepaired(first, definitionUuid, new TimeAttributeContentV3(LocalTime.of(18, 0)), "time");
    }

    @Test
    void migrate_repairsMoreRowsThanOneBatchStages() throws Exception {
        UUID definitionUuid = definition("validUntil", AttributeContentType.DATE, ProtectionLevel.NONE);
        int rows = 1001;
        try (Connection connection = dataSource.getConnection();
                PreparedStatement insert = connection.prepareStatement("""
                        INSERT INTO attribute_content_item (uuid, attribute_definition_uuid, json)
                        SELECT gen_random_uuid(), ?, jsonb_build_object('reference', NULL, 'contentType', 'date',
                               'data', jsonb_build_array(extract(YEAR FROM day)::INT, extract(MONTH FROM day)::INT,
                                                         extract(DAY FROM day)::INT))
                          FROM generate_series(DATE '2000-01-01', DATE '2000-01-01' + ?, INTERVAL '1 day') AS day
                        """)) {
            insert.setObject(1, definitionUuid);
            insert.setInt(2, rows - 1);
            assertThat(insert.executeUpdate()).isEqualTo(rows);
        }

        runMigration();

        assertThat(textValueCount(definitionUuid)).isEqualTo(rows);
        LocalDate lastDay = LocalDate.of(2000, 1, 1).plusDays(rows - 1L);
        assertThat(attributeContentItemRepository
                .findPlaintextUuid(definitionUuid, AttributeContentJson.render(new DateAttributeContentV3(lastDay))))
                .isNotNull();
    }

    @Test
    void migrate_leavesRowsTheDefectDidNotWriteAsTheyAre() throws Exception {
        UUID datetimeDefinition = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID integerDefinition = definition("retries", AttributeContentType.INTEGER, ProtectionLevel.NONE);
        UUID encryptedDefinition = definition("sealedAt", AttributeContentType.DATETIME, ProtectionLevel.ENCRYPTED);
        UUID dateDefinition = definition("validUntil", AttributeContentType.DATE, ProtectionLevel.NONE);
        List<UUID> untouched = new ArrayList<>();
        // Releases before typed content stored the text the client sent, in the @JsonFormat pattern.
        untouched
                .add(storedItem(datetimeDefinition,
                        "{\"reference\": null, \"data\": \"2024-08-27T13:40:19.000Z\", \"contentType\": \"datetime\"}"));
        untouched
                .add(itemOf(certificateWriting(integerDefinition, new IntegerAttributeContentV3(5)),
                        integerDefinition));
        // The guard on encryption, not the placeholder's null value, keeps an encrypted row out.
        untouched
                .add(storedItem(encryptedDefinition,
                        "{\"reference\": null, \"data\": 1768469400.000000000, \"contentType\": \"datetime\"}"));
        // Shapes no java.time value serializes to: one bad row must not stop the upgrade.
        untouched
                .add(storedItem(dateDefinition,
                        "{\"reference\": null, \"data\": 20260329, \"contentType\": \"date\"}"));
        untouched
                .add(storedItem(dateDefinition,
                        "{\"reference\": null, \"data\": [2026, 3], \"contentType\": \"date\"}"));
        untouched
                .add(storedItem(dateDefinition,
                        "{\"reference\": null, \"data\": [2026, 2, 30], \"contentType\": \"date\"}"));
        // The column mapper always wrote nine decimal places; a number without them came from somewhere else.
        untouched
                .add(storedItem(datetimeDefinition,
                        "{\"reference\": null, \"data\": 1768469400, \"contentType\": \"datetime\"}"));
        // Before Jackson 2.21 this text held -0.5 seconds, and from 2.21 it holds -1.5: which one is unknowable.
        untouched
                .add(storedItem(datetimeDefinition,
                        "{\"reference\": null, \"data\": -1.500000000, \"contentType\": \"datetime\"}"));
        List<String> before = untouched.stream().map(this::storedJsonOrNull).toList();

        runMigration();

        assertThat(untouched.stream().map(this::storedJsonOrNull).toList()).isEqualTo(before);
    }

    @Test
    void migrate_holdsOffWritesToTheContentTablesUntilItCommits() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                migrate(connection);
                assertThat(locksHeld(connection))
                        .containsExactlyInAnyOrder("attribute_content_item ShareRowExclusiveLock",
                                "attribute_content_2_object ShareRowExclusiveLock");
            } finally {
                connection.rollback();
                connection.setAutoCommit(true);
            }
        }
    }

    // --- helpers ---

    private void assertRepaired(UUID certificateUuid, UUID definitionUuid, AttributeContent expected, String sqlType)
            throws SQLException {
        UUID itemUuid = itemOf(certificateUuid, definitionUuid);
        String expectedJson = AttributeContentJson.render(expected);
        assertThat(attributeContentItemRepository.findPlaintextUuid(definitionUuid, expectedJson))
                .as("a write of %s today finds the repaired row", expectedJson)
                .isEqualTo(itemUuid);
        assertThat(castData(itemUuid, sqlType))
                .as("the search cast to %s accepts the repaired value", sqlType)
                .isNotNull();
    }

    /** Runs the migration in one transaction, as Flyway does, so its read goes through a cursor. */
    private void runMigration() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                migrate(connection);
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    private static void migrate(Connection connection) throws SQLException {
        Context context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
        new V202610181200__RepairDateAttributeContent().migrate(context);
    }

    private UUID definition(String name, AttributeContentType contentType, ProtectionLevel protectionLevel)
            throws AttributeException {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setProtectionLevel(protectionLevel);
        attribute.setProperties(properties);
        return attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CERTIFICATE)).getUuid();
    }

    private void ownedByConnector(UUID definitionUuid, AttributeType type, int version) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement update = connection
                        .prepareStatement("UPDATE attribute_definition SET type = ?, version = ? WHERE uuid = ?")) {
            update.setString(1, type.name());
            update.setInt(2, version);
            update.setObject(3, definitionUuid);
            assertThat(update.executeUpdate()).isEqualTo(1);
        }
    }

    private UUID certificateWriting(UUID definitionUuid, AttributeContent content)
            throws NotFoundException, AttributeException {
        UUID certificateUuid = certificateRepository.save(new Certificate()).getUuid();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                        List.of(content), attributeEngine.loadCustomAttributesSecurityResourceFilter());
        return certificateUuid;
    }

    /**
     * A certificate whose value of the definition is stored as the given JSON. The engine writes a distinct placeholder
     * of the definition's content type first, so the row and its mapping are the engine's own and no other certificate
     * shares the row.
     */
    private UUID certificateHoldingStored(UUID definitionUuid, String storedJson) throws Exception {
        UUID certificateUuid = certificateWriting(definitionUuid, placeholder(contentTypeOf(definitionUuid)));
        storeJson(itemOf(certificateUuid, definitionUuid), storedJson);
        return certificateUuid;
    }

    private UUID storedItem(UUID definitionUuid, String storedJson) throws Exception {
        return itemOf(certificateHoldingStored(definitionUuid, storedJson), definitionUuid);
    }

    private AttributeContent placeholder(AttributeContentType contentType) {
        int sequence = placeholderSequence.incrementAndGet();
        return switch (contentType) {
            case DATE -> new DateAttributeContentV3(LocalDate.of(1990, 1, 1).plusDays(sequence));
            case TIME -> new TimeAttributeContentV3(LocalTime.of(1, 0).plusMinutes(sequence));
            case DATETIME -> new DateTimeAttributeContentV3(
                    ZonedDateTime.of(1990, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).plusSeconds(sequence));
            default -> throw new IllegalArgumentException("No placeholder for " + contentType);
        };
    }

    private static <T extends AttributeContent> T referenced(T content, String reference) {
        if (content instanceof DateAttributeContentV3 date) {
            date.setReference(reference);
        } else if (content instanceof TimeAttributeContentV3 time) {
            time.setReference(reference);
        }
        return content;
    }

    private AttributeContentType contentTypeOf(UUID definitionUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection
                        .prepareStatement("SELECT content_type FROM attribute_definition WHERE uuid = ?")) {
            select.setObject(1, definitionUuid);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                return AttributeContentType.valueOf(rows.getString(1));
            }
        }
    }

    private ZonedDateTime storedDatetime(UUID certificateUuid, String attributeName) {
        Object data = attributeEngine
                .getObjectCustomAttributesContent(Resource.CERTIFICATE, certificateUuid)
                .stream()
                .filter(attribute -> attributeName.equals(attribute.getName()))
                .flatMap(attribute -> ((ResponseAttributeV3) attribute).getContent().stream())
                .map(AttributeContent::getData)
                .findFirst()
                .orElseThrow();
        return (ZonedDateTime) data;
    }

    private UUID itemOf(UUID certificateUuid, UUID definitionUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection.prepareStatement("""
                        SELECT item.uuid FROM attribute_content_item item
                          JOIN attribute_content_2_object mapping ON mapping.attribute_content_item_uuid = item.uuid
                         WHERE mapping.object_uuid = ? AND item.attribute_definition_uuid = ?
                        """)) {
            select.setObject(1, certificateUuid);
            select.setObject(2, definitionUuid);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                UUID itemUuid = rows.getObject(1, UUID.class);
                assertThat(rows.next()).as("the certificate holds one value of the definition").isFalse();
                return itemUuid;
            }
        }
    }

    private void storeJson(UUID itemUuid, String json) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement update = connection
                        .prepareStatement("UPDATE attribute_content_item SET json = CAST(? AS jsonb) WHERE uuid = ?")) {
            update.setString(1, json);
            update.setObject(2, itemUuid);
            assertThat(update.executeUpdate()).isEqualTo(1);
        }
    }

    private String storedJsonOrNull(UUID itemUuid) {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection
                        .prepareStatement("SELECT json::text FROM attribute_content_item WHERE uuid = ?")) {
            select.setObject(1, itemUuid);
            try (ResultSet rows = select.executeQuery()) {
                return rows.next() ? rows.getString(1) : null;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private Object castData(UUID itemUuid, String sqlType) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection
                        .prepareStatement("SELECT CAST(json->>'data' AS " + sqlType
                                + ") FROM attribute_content_item WHERE uuid = ?")) {
            select.setObject(1, itemUuid);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                return rows.getObject(1);
            }
        }
    }

    private long textValueCount(UUID definitionUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection.prepareStatement("""
                        SELECT count(*) FROM attribute_content_item
                         WHERE attribute_definition_uuid = ? AND jsonb_typeof(json->'data') = 'string'
                        """)) {
            select.setObject(1, definitionUuid);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    private static List<String> locksHeld(Connection connection) throws SQLException {
        List<String> locks = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement("""
                SELECT relation.relname, held.mode FROM pg_locks held
                  JOIN pg_class relation ON relation.oid = held.relation
                 WHERE held.pid = pg_backend_pid() AND held.granted
                   AND relation.relname IN ('attribute_content_item', 'attribute_content_2_object')
                   AND held.mode = 'ShareRowExclusiveLock'
                """); ResultSet rows = select.executeQuery()) {
            while (rows.next()) {
                locks.add(rows.getString(1) + " " + rows.getString(2));
            }
        }
        return locks;
    }

    private void mapAlso(UUID certificateUuid, UUID itemUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement insert = connection.prepareStatement("""
                        INSERT INTO attribute_content_2_object (uuid, attribute_content_item_uuid, object_type,
                                                                object_uuid, item_order)
                        VALUES (gen_random_uuid(), ?, 'CERTIFICATE', ?, 0)
                        """)) {
            insert.setObject(1, itemUuid);
            insert.setObject(2, certificateUuid);
            insert.executeUpdate();
        }
    }

    private long mappingCount(UUID certificateUuid, UUID itemUuid) throws SQLException {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement select = connection.prepareStatement("""
                        SELECT count(*) FROM attribute_content_2_object
                         WHERE object_uuid = ? AND attribute_content_item_uuid = ?
                        """)) {
            select.setObject(1, certificateUuid);
            select.setObject(2, itemUuid);
            try (ResultSet rows = select.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }
}
