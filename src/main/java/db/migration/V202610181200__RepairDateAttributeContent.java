package db.migration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.DateAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateTimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TimeAttributeContentV3;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.util.UUID;

/**
 * Rewrites the Date, Time and Datetime attribute values that releases before 2.20.0 stored as numbers and arrays. Their
 * column mapper wrote a Date as {@code [year, month, day]}, a Time as {@code [hour, minute, second, nano]} with trailing
 * zeros left out, and a Datetime as epoch seconds with nine decimal places, the epoch itself as {@code 0.0}: the search
 * casts reject all three, and a Datetime cannot be read back at all. It wrote that way whatever held a
 * {@code java.time} value: typed version 3 content, and the version 2 content those releases decrypted when a
 * definition's encryption was turned off, which carries no content type of its own.
 * <p>
 * Each value is decoded and rendered as text the way 2.20.0 writes it, so the lookup by value finds it. A Datetime
 * comes back in UTC: the number held the exact instant, but not the offset it was entered with. Rows in a shape that
 * mapper never wrote are not selected. A selected row that does not decode to a value is left as it is and logged, and
 * so is a Datetime before 1970 with a fraction of a second: Jackson 2.21 changed how it writes and reads one, so its
 * text means two instants a second apart depending on the release that wrote it.
 * <p>
 * The values are decoded one row at a time, but staged and written back in a few set-based statements, so the time the
 * migration holds Core's startup does not grow with a round trip per row. Repaired values a definition then holds twice
 * - because a write after the upgrade could not match its value to the number, or two shapes held one value - fold onto
 * one row, and a row that was already text is the one kept. Writes to the two tables wait until the migration commits:
 * during a rolling update the previous release keeps writing while it runs.
 */
// Flyway requires the V<timestamp>__Name class name to resolve the migration version; it cannot match S101's
// class-name pattern.
@SuppressWarnings("java:S101")
public class V202610181200__RepairDateAttributeContent extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202610181200__RepairDateAttributeContent.class);

    private static final int BATCH_SIZE = 500;

    /**
     * The column recipe as 2.20.0 states it, pinned here: a migration has to decode and write the same on every release
     * that runs it, and the application's recipe moves with the release.
     */
    private static final ObjectMapper COLUMN_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /** Writes content through its declared type, as Hibernate writes the column. */
    private static final ObjectWriter CONTENT_WRITER = COLUMN_MAPPER.writerFor(AttributeContent.class);

    private static final String LOCK_CONTENT_TABLES = """
            LOCK TABLE attribute_content_item, attribute_content_2_object IN SHARE ROW EXCLUSIVE MODE
            """;

    private static final String SELECT_BROKEN_ITEMS = """
            SELECT item.uuid, item.attribute_definition_uuid, definition.content_type,
                   jsonb_typeof(item.json->'contentType') = 'string' AS typed,
                   item.json->'data' AS data, item.json->>'reference' AS reference
              FROM attribute_content_item item
              JOIN attribute_definition definition ON definition.uuid = item.attribute_definition_uuid
             WHERE item.encrypted_data IS NULL
               AND jsonb_typeof(item.json->'contentType') IN ('string', 'null')
               AND ((definition.content_type IN ('DATE', 'TIME') AND jsonb_typeof(item.json->'data') = 'array')
                 OR (definition.content_type = 'DATETIME'
                     AND CASE WHEN jsonb_typeof(item.json->'data') = 'number'
                              THEN scale((item.json->>'data')::NUMERIC) = 9 OR item.json->>'data' = '0.0'
                              ELSE FALSE END))
            """;

    private static final String CREATE_REPAIRED = """
            CREATE TEMP TABLE repaired_date_attribute_content (
                uuid UUID PRIMARY KEY,
                attribute_definition_uuid UUID NOT NULL,
                json JSONB NOT NULL
            )
            """;

    private static final String INSERT_REPAIRED = """
            INSERT INTO repaired_date_attribute_content (uuid, attribute_definition_uuid, json)
            VALUES (?, ?, CAST(? AS jsonb))
            """;

    private static final String ANALYZE_REPAIRED = "ANALYZE repaired_date_attribute_content";

    /**
     * Pairs each repaired row with the row its value is kept in. Values are matched on the text the column's digest is
     * taken from, as {@code V202610061000} matches them.
     */
    private static final String CREATE_FOLD = """
            CREATE TEMP TABLE repaired_date_attribute_content_fold AS
            SELECT ranked.uuid AS duplicate_uuid, ranked.keep_uuid
              FROM (SELECT candidate.uuid, candidate.repaired,
                           first_value(candidate.uuid) OVER (PARTITION BY candidate.attribute_definition_uuid,
                                                                          candidate.value_text
                                                             ORDER BY candidate.repaired, candidate.uuid) AS keep_uuid
                      FROM (SELECT repaired.uuid, repaired.attribute_definition_uuid, repaired.json::TEXT AS value_text,
                                   TRUE AS repaired
                              FROM repaired_date_attribute_content repaired
                             UNION ALL
                            SELECT item.uuid, item.attribute_definition_uuid, item.json::TEXT, FALSE
                              FROM attribute_content_item item
                             WHERE item.encrypted_data IS NULL
                               AND item.attribute_definition_uuid IN
                                   (SELECT attribute_definition_uuid FROM repaired_date_attribute_content)
                               AND NOT EXISTS (SELECT 1 FROM repaired_date_attribute_content repaired
                                                WHERE repaired.uuid = item.uuid)) AS candidate) AS ranked
             WHERE ranked.repaired AND ranked.uuid <> ranked.keep_uuid
            """;

    private static final String MOVE_FOLDED_MAPPINGS = """
            UPDATE attribute_content_2_object mapping
               SET attribute_content_item_uuid = fold.keep_uuid
              FROM repaired_date_attribute_content_fold fold
             WHERE mapping.attribute_content_item_uuid = fold.duplicate_uuid
            """;

    /** An object that was mapped to more than one of the folded rows now holds the same mapping twice: keep one. */
    private static final String DELETE_REPEATED_MAPPINGS = """
            DELETE FROM attribute_content_2_object mapping
             USING attribute_content_2_object kept
             WHERE mapping.attribute_content_item_uuid IN (SELECT keep_uuid FROM repaired_date_attribute_content_fold)
               AND kept.attribute_content_item_uuid = mapping.attribute_content_item_uuid
               AND kept.uuid < mapping.uuid
               AND kept.object_type = mapping.object_type
               AND kept.object_uuid = mapping.object_uuid
               AND kept.connector_uuid IS NOT DISTINCT FROM mapping.connector_uuid
               AND kept.source_object_type IS NOT DISTINCT FROM mapping.source_object_type
               AND kept.source_object_uuid IS NOT DISTINCT FROM mapping.source_object_uuid
               AND kept.purpose IS NOT DISTINCT FROM mapping.purpose
               AND kept.object_version IS NOT DISTINCT FROM mapping.object_version
            """;

    private static final String DELETE_FOLDED_ITEMS = """
            DELETE FROM attribute_content_item item
             USING repaired_date_attribute_content_fold fold
             WHERE item.uuid = fold.duplicate_uuid
            """;

    /** Runs after the fold, so no two rows of a definition are left to take one value. */
    private static final String REWRITE_ITEMS = """
            UPDATE attribute_content_item item
               SET json = repaired.json
              FROM repaired_date_attribute_content repaired
             WHERE item.uuid = repaired.uuid
            """;

    private static final String DROP_STAGING = "DROP TABLE repaired_date_attribute_content_fold, repaired_date_attribute_content";

    private record BrokenItem(UUID uuid, UUID definitionUuid, AttributeContentType contentType, boolean typed,
            String data, String reference) {
    }

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202610181200__RepairDateAttributeContent.getChecksum();
    }

    @Override
    public void migrate(Context context) throws SQLException {
        Connection connection = context.getConnection();
        try (Statement statement = connection.createStatement()) {
            statement.execute(LOCK_CONTENT_TABLES);
            statement.execute(CREATE_REPAIRED);
            int skipped = stageRepairedValues(connection);
            statement.execute(ANALYZE_REPAIRED);
            statement.execute(CREATE_FOLD);
            statement.executeUpdate(MOVE_FOLDED_MAPPINGS);
            statement.executeUpdate(DELETE_REPEATED_MAPPINGS);
            int folded = statement.executeUpdate(DELETE_FOLDED_ITEMS);
            int rewritten = statement.executeUpdate(REWRITE_ITEMS);
            statement.execute(DROP_STAGING);
            logger.info("Date, Time and Datetime attribute content repaired: {} rows rewritten, {} rows folded into the"
                    + " row holding their value, {} rows left as they are.", rewritten, folded, skipped);
        }
    }

    /**
     * Stages the repaired value of every broken row, reading the rows through a cursor: Flyway runs the migration with
     * autocommit off, so the fetch size bounds what is held in memory. Returns the number of rows left as they are.
     */
    private static int stageRepairedValues(Connection connection) throws SQLException {
        int skipped = 0;
        int pending = 0;
        try (Statement select = connection.createStatement();
                PreparedStatement insert = connection.prepareStatement(INSERT_REPAIRED)) {
            select.setFetchSize(BATCH_SIZE);
            try (ResultSet rows = select.executeQuery(SELECT_BROKEN_ITEMS)) {
                while (rows.next()) {
                    BrokenItem item = brokenItem(rows);
                    String repairedJson = repairedJson(item);
                    if (repairedJson == null) {
                        skipped++;
                        continue;
                    }
                    insert.setObject(1, item.uuid());
                    insert.setObject(2, item.definitionUuid());
                    insert.setString(3, repairedJson);
                    insert.addBatch();
                    if (++pending == BATCH_SIZE) {
                        insert.executeBatch();
                        pending = 0;
                    }
                }
            }
            if (pending > 0) {
                insert.executeBatch();
            }
        }
        return skipped;
    }

    private static BrokenItem brokenItem(ResultSet row) throws SQLException {
        UUID uuid = row.getObject("uuid", UUID.class);
        UUID definitionUuid = row.getObject("attribute_definition_uuid", UUID.class);
        AttributeContentType contentType = AttributeContentType.valueOf(row.getString("content_type"));
        return new BrokenItem(uuid, definitionUuid, contentType, row.getBoolean("typed"), row.getString("data"),
                row.getString("reference"));
    }

    /** The row's value as a write of it stores it today, or {@code null} when the row is left as it is. */
    private static String repairedJson(BrokenItem item) {
        if (item.contentType() == AttributeContentType.DATETIME && isBeforeTheEpochWithAFraction(item.data())) {
            logger.warn("Leaving attribute content item {} as it is: its Datetime value is before 1970 with a fraction of"
                    + " a second, which releases on Jackson 2.20 and earlier stored as a different instant than later"
                    + " ones.", item.uuid());
            return null;
        }
        try {
            Serializable value = decodedValue(item);
            if (value == null) {
                logger.warn("Leaving attribute content item {} as it is: its {} value decodes to no value.", item.uuid(),
                        item.contentType());
                return null;
            }
            AttributeContent content = item.typed() ? typedContent(item, value)
                    : new BaseAttributeContentV2<>(item.reference(), value);
            return CONTENT_WRITER.writeValueAsString(content);
        } catch (JsonProcessingException | DateTimeException e) {
            logger.warn("Leaving attribute content item {} as it is: its {} value is not in the shape the column mapper"
                    + " wrote before 2.20.0. Cause: {}", item.uuid(), item.contentType(), e.getMessage());
            return null;
        }
    }

    private static boolean isBeforeTheEpochWithAFraction(String epochSeconds) {
        BigDecimal value = new BigDecimal(epochSeconds);
        return value.signum() < 0 && value.stripTrailingZeros().scale() > 0;
    }

    /**
     * Decodes the arrays and decimal seconds from the stored text, so no double rounds the nanoseconds. An empty array
     * decodes to {@code null}.
     */
    private static Serializable decodedValue(BrokenItem item) throws JsonProcessingException {
        return switch (item.contentType()) {
            case DATE -> COLUMN_MAPPER.readValue(item.data(), LocalDate.class);
            case TIME -> COLUMN_MAPPER.readValue(item.data(), LocalTime.class);
            case DATETIME -> COLUMN_MAPPER.readValue(item.data(), ZonedDateTime.class);
            default -> throw new IllegalStateException("Content type " + item.contentType() + " is not repaired");
        };
    }

    private static AttributeContent typedContent(BrokenItem item, Serializable value) {
        return switch (value) {
            case LocalDate date -> {
                DateAttributeContentV3 content = new DateAttributeContentV3(date);
                content.setReference(item.reference());
                yield content;
            }
            case LocalTime time -> {
                TimeAttributeContentV3 content = new TimeAttributeContentV3(time);
                content.setReference(item.reference());
                yield content;
            }
            case ZonedDateTime dateTime -> new DateTimeAttributeContentV3(item.reference(), dateTime);
            default -> throw new IllegalStateException("No content type holds " + value.getClass().getSimpleName());
        };
    }
}
