package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202609291500__crypto_asset_source_bom_refs.sql} over rows in the shape the tables had before it.
 *
 * <p>
 * The suite's schema is generated from the entities, so the migration's own statement runs nowhere else. It adds the
 * column and does nothing more. The refs cannot be derived in SQL, and a released upgrade reaches it with the source
 * table still empty, so no record is put back on the ingest work list. Re-offering the synced records would re-read
 * every document from the CBOM Repository and fail each one no longer there, a cost only an operator who wants the
 * links sooner should choose. The test pins that the migration writes no sync state.
 */
class CryptoAssetSourceBomRefsMigrationITest extends BaseSpringBootTest {

    private static final String INVENTORY_RESOURCE = "db/migration/V202608271000__crypto_asset_inventory.sql";

    private static final String BOM_REFS_RESOURCE = "db/migration/V202609291500__crypto_asset_source_bom_refs.sql";

    private static final String SCRATCH_SCHEMA = "crypto_asset_source_bom_refs_migration_check";

    /**
     * The table as the inventory migration finds it, cut to what this test touches: {@code uuid}, which the source
     * table references, and the {@code serial_number} and {@code version} the seed writes. The migration adds the
     * {@code asset_sync_state} and {@code assets_synced_at} the test seeds and reads.
     */
    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL
            )
            """;

    private static final UUID ASSET = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID SYNCED_WITH_SOURCE = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID NOT_YET_INGESTED = UUID.fromString("00000000-0000-4000-8000-000000000003");

    @Autowired
    private DataSource dataSource;

    @Test
    void addsTheColumnEmptyAndLeavesEverySyncStateAlone() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigration(connection);
                seed(connection);
                Map<UUID, String> statesBefore = syncStates(connection);
                applyBomRefsMigration(connection);

                assertThat(columnFacts(connection))
                        .describedAs("data_type|is_nullable|column_default")
                        .isEqualTo("ARRAY|NO|'{}'::text[]");
                assertThat(storedRefs(connection, SYNCED_WITH_SOURCE))
                        .describedAs("an existing source row reads an empty array, not null")
                        .isEqualTo("{}");
                assertThat(syncStates(connection))
                        .describedAs("no automatic re-sync: every record keeps its state, a synced one holding source"
                                + " rows included")
                        .isEqualTo(statesBefore)
                        .containsEntry(SYNCED_WITH_SOURCE, "SYNCED");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /** The previous release's insert names no bom_refs; during a rolling deploy it must still succeed. */
    @Test
    void anInsertThatNamesNoRefsStoresAnEmptyArray() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigration(connection);
                seed(connection);
                applyBomRefsMigration(connection);

                try (Statement statement = connection.createStatement()) {
                    statement.execute("""
                            INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)
                            VALUES (gen_random_uuid(), '%s', '%s', now(), now())
                            """.formatted(ASSET, NOT_YET_INGESTED));
                }

                assertThat(storedRefs(connection, NOT_YET_INGESTED)).isEqualTo("{}");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyInventoryMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(INVENTORY_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name cannot resolve to the entity-generated
            // core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(CBOM_STUB);
            statement.execute(migration);
        }
    }

    private void applyBomRefsMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(BOM_REFS_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void seed(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO cbom (uuid, serial_number, version, asset_sync_state, assets_synced_at) VALUES
                        ('%s', 'urn:uuid:synced-with-source', 1, 'SYNCED', now()),
                        ('%s', 'urn:uuid:not-yet-ingested', 1, 'PENDING', NULL)
                    """.formatted(SYNCED_WITH_SOURCE, NOT_YET_INGESTED));
            statement.execute("""
                    INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, i_cre, i_upd)
                    VALUES ('%s', 'key-1', 3, 'ALGORITHM', now(), now())
                    """.formatted(ASSET));
            statement.execute("""
                    INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)
                    VALUES (gen_random_uuid(), '%s', '%s', now(), now())
                    """.formatted(ASSET, SYNCED_WITH_SOURCE));
        }
    }

    private String columnFacts(Connection connection) throws SQLException {
        return queryOne(connection, """
                SELECT data_type || '|' || is_nullable || '|' || column_default FROM information_schema.columns
                WHERE table_schema = '%s' AND table_name = 'crypto_asset_source' AND column_name = 'bom_refs'
                """.formatted(SCRATCH_SCHEMA));
    }

    private String storedRefs(Connection connection, UUID cbomUuid) throws SQLException {
        return queryOne(connection,
                "SELECT bom_refs::TEXT FROM crypto_asset_source WHERE cbom_uuid = '%s'".formatted(cbomUuid));
    }

    private Map<UUID, String> syncStates(Connection connection) throws SQLException {
        Map<UUID, String> states = new HashMap<>();
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT uuid, asset_sync_state FROM cbom")) {
            while (rows.next()) {
                states.put(rows.getObject(1, UUID.class), rows.getString(2));
            }
        }
        return states;
    }

    private String queryOne(Connection connection, String sql) throws SQLException {
        List<String> values = new ArrayList<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                values.add(rows.getString(1));
            }
        }
        assertThat(values).describedAs("exactly one row for %s", sql.toLowerCase(Locale.ROOT)).hasSize(1);
        return values.get(0);
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }
}
