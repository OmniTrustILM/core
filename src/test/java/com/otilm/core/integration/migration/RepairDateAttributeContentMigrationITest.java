package com.otilm.core.integration.migration;

import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
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
import com.otilm.core.serialization.ObjectMapperFactory;
import db.migration.V202610181200__RepairDateAttributeContent;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Rows of Date, Time and Datetime attributes stored before 2.20.0 hold a number or an array, which the search casts
 * reject and the Datetime reader cannot parse. The repair has to leave each one exactly as a write of the same value
 * stores it today, or the lookup by value misses it and the definition holds the value twice.
 */
class RepairDateAttributeContentMigrationITest extends BaseMigrationTest {

    /** The column mapper as it stood before dates were written as text. */
    private static final ObjectWriter PRE_2_20_COLUMN_WRITER = ObjectMapperFactory
            .jsonColumn()
            .enable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .writerFor(AttributeContent.class);

    @Autowired
    private DataSource dataSource;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private AttributeContentItemRepository attributeContentItemRepository;

    @Test
    void migrate_rewritesEachValueAsAWriteOfItStoresItToday() throws Exception {
        UUID dateDefinition = definition("validUntil", AttributeContentType.DATE, ProtectionLevel.NONE);
        UUID timeDefinition = definition("maintenanceAt", AttributeContentType.TIME, ProtectionLevel.NONE);
        UUID datetimeDefinition = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        LocalDate date = LocalDate.of(2026, 3, 29);
        LocalTime wholeMinute = LocalTime.of(18, 0);
        LocalTime withSeconds = LocalTime.of(18, 0, 5);
        ZonedDateTime enteredWithOffset = ZonedDateTime.of(2026, 1, 15, 11, 30, 0, 123_000_000, ZoneOffset.ofHours(2));
        ZonedDateTime beforeTheEpoch = ZonedDateTime.of(1969, 12, 31, 23, 59, 59, 500_000_000, ZoneOffset.UTC);

        UUID dateCertificate = certificateHoldingPre220Value(dateDefinition, new DateAttributeContentV3(date));
        UUID wholeMinuteCertificate = certificateHoldingPre220Value(timeDefinition,
                new TimeAttributeContentV3(wholeMinute));
        UUID withSecondsCertificate = certificateHoldingPre220Value(timeDefinition,
                new TimeAttributeContentV3(withSeconds));
        UUID offsetCertificate = certificateHoldingPre220Value(datetimeDefinition,
                new DateTimeAttributeContentV3(enteredWithOffset));
        UUID epochCertificate = certificateHoldingPre220Value(datetimeDefinition,
                new DateTimeAttributeContentV3(beforeTheEpoch));

        runMigration();

        assertRepaired(dateCertificate, dateDefinition, new DateAttributeContentV3(date), "date");
        assertRepaired(wholeMinuteCertificate, timeDefinition, new TimeAttributeContentV3(wholeMinute), "time");
        assertRepaired(withSecondsCertificate, timeDefinition, new TimeAttributeContentV3(withSeconds), "time");
        assertRepaired(offsetCertificate, datetimeDefinition,
                new DateTimeAttributeContentV3(enteredWithOffset.withZoneSameInstant(ZoneOffset.UTC)), "timestamptz");
        assertRepaired(epochCertificate, datetimeDefinition, new DateTimeAttributeContentV3(beforeTheEpoch),
                "timestamptz");

        assertThat(storedDatetime(offsetCertificate, "reviewedAt").toInstant())
                .as("the stored number was the exact instant: only the offset it was entered with is gone")
                .isEqualTo(enteredWithOffset.toInstant());
        assertThat(storedDatetime(epochCertificate, "reviewedAt"))
                .as("a value before 1970 was stored as negative seconds and positive nanoseconds")
                .isEqualTo(beforeTheEpoch);
    }

    @Test
    void migrate_foldsARepairedValueIntoTheRowAWriteAfterTheUpgradeStoredForIt() throws Exception {
        UUID definitionUuid = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        DateTimeAttributeContentV3 value = new DateTimeAttributeContentV3(
                ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 0, ZoneOffset.UTC));
        UUID beforeUpgrade = certificateHoldingPre220Value(definitionUuid, value);
        UUID brokenItem = itemOf(beforeUpgrade, definitionUuid);
        UUID afterUpgrade = certificateHolding(definitionUuid, value);
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
        assertThat(storedDatetime(beforeUpgrade, "reviewedAt")).isEqualTo(value.getData());
        assertThat(storedDatetime(afterUpgrade, "reviewedAt")).isEqualTo(value.getData());
    }

    @Test
    void migrate_foldsBrokenRowsThatRepairToTheSameValueIntoOne() throws Exception {
        UUID definitionUuid = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        DateTimeAttributeContentV3 value = new DateTimeAttributeContentV3(
                ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 123_000_000, ZoneOffset.UTC));
        UUID first = certificateHoldingPre220Value(definitionUuid, value);
        UUID second = certificateHolding(definitionUuid,
                new DateTimeAttributeContentV3(ZonedDateTime.of(2026, 1, 15, 9, 31, 0, 0, ZoneOffset.UTC)));
        // The same instant at another written precision: a second row, which jsonb keeps apart from the first.
        storeJson(itemOf(second, definitionUuid),
                "{\"reference\": null, \"data\": 1768469400.123, \"contentType\": \"datetime\"}");

        runMigration();

        assertThat(itemOf(first, definitionUuid)).isEqualTo(itemOf(second, definitionUuid));
        assertThat(storedDatetime(first, "reviewedAt")).isEqualTo(value.getData());
        assertThat(storedDatetime(second, "reviewedAt")).isEqualTo(value.getData());
    }

    @Test
    void migrate_leavesRowsTheDefectDidNotWriteAsTheyAre() throws Exception {
        UUID datetimeDefinition = definition("reviewedAt", AttributeContentType.DATETIME, ProtectionLevel.NONE);
        UUID integerDefinition = definition("retries", AttributeContentType.INTEGER, ProtectionLevel.NONE);
        UUID encryptedDefinition = definition("sealedAt", AttributeContentType.DATETIME, ProtectionLevel.ENCRYPTED);
        UUID dateDefinition = definition("validUntil", AttributeContentType.DATE, ProtectionLevel.NONE);

        UUID olderTextItem = itemOf(
                certificateHolding(datetimeDefinition,
                        new DateTimeAttributeContentV3(ZonedDateTime.of(2024, 8, 27, 13, 40, 19, 0, ZoneOffset.UTC))),
                datetimeDefinition);
        // Releases before typed content stored the text the client sent, in the @JsonFormat pattern.
        storeJson(olderTextItem,
                "{\"reference\": null, \"data\": \"2024-08-27T13:40:19.000Z\", \"contentType\": \"datetime\"}");
        UUID integerItem = itemOf(certificateHolding(integerDefinition, new IntegerAttributeContentV3(5)),
                integerDefinition);
        UUID encryptedItem = itemOf(
                certificateHolding(encryptedDefinition,
                        new DateTimeAttributeContentV3(ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 0, ZoneOffset.UTC))),
                encryptedDefinition);
        UUID unknownShapeItem = itemOf(
                certificateHolding(dateDefinition, new DateAttributeContentV3(LocalDate.of(2026, 3, 29))),
                dateDefinition);
        storeJson(unknownShapeItem, "{\"reference\": null, \"data\": 20260329, \"contentType\": \"date\"}");
        // Arrays no java.time value serializes to: one bad row must not stop the upgrade.
        UUID shortArrayItem = itemOf(
                certificateHolding(dateDefinition, new DateAttributeContentV3(LocalDate.of(2026, 3, 30))),
                dateDefinition);
        storeJson(shortArrayItem, "{\"reference\": null, \"data\": [2026, 3], \"contentType\": \"date\"}");
        UUID impossibleDateItem = itemOf(
                certificateHolding(dateDefinition, new DateAttributeContentV3(LocalDate.of(2026, 3, 31))),
                dateDefinition);
        storeJson(impossibleDateItem, "{\"reference\": null, \"data\": [2026, 2, 30], \"contentType\": \"date\"}");
        List<UUID> untouched = List
                .of(olderTextItem, integerItem, encryptedItem, unknownShapeItem, shortArrayItem, impossibleDateItem);
        List<String> before = untouched.stream().map(this::storedJsonOrNull).toList();

        runMigration();

        assertThat(untouched.stream().map(this::storedJsonOrNull).toList()).isEqualTo(before);
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
                Context context = mock(Context.class);
                when(context.getConnection()).thenReturn(connection);
                new V202610181200__RepairDateAttributeContent().migrate(context);
                connection.commit();
            } finally {
                connection.setAutoCommit(true);
            }
        }
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

    private UUID certificateHolding(UUID definitionUuid, AttributeContent content)
            throws NotFoundException, AttributeException {
        UUID certificateUuid = certificateRepository.save(new Certificate()).getUuid();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid, definitionUuid, null,
                        List.of(content), attributeEngine.loadCustomAttributesSecurityResourceFilter());
        return certificateUuid;
    }

    private UUID certificateHoldingPre220Value(UUID definitionUuid, AttributeContent content) throws Exception {
        UUID certificateUuid = certificateHolding(definitionUuid, content);
        storeJson(itemOf(certificateUuid, definitionUuid), PRE_2_20_COLUMN_WRITER.writeValueAsString(content));
        return certificateUuid;
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
