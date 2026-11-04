package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Runs {@code V202610221200__crypto_asset_pqc_verdict_by_reference.sql} over the inventory as the migrations before it
 * leave it: the widened kind check admits the new reference kinds, every key, certificate and protocol row is
 * re-offered to the sweep while an algorithm is not, and a synced document is re-queued only when it still sources a
 * key or a protocol.
 */
class CryptoAssetPqcVerdictByReferenceMigrationITest extends BaseSpringBootTest {

    private static final List<String> INVENTORY_RESOURCES = List
            .of("db/migration/V202608271000__crypto_asset_inventory.sql",
                    "db/migration/V202609141000__crypto_asset_curve_membership.sql",
                    "db/migration/V202609291200__crypto_asset_pqc_references.sql");

    private static final String MIGRATION_RESOURCE = "db/migration/V202610221200__crypto_asset_pqc_verdict_by_reference.sql";

    private static final String SCRATCH_SCHEMA = "crypto_asset_pqc_verdict_by_reference_check";

    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL,
                "asset_sync_content_refusals" INT NOT NULL DEFAULT 0
            )
            """;

    private static final String KEY_CBOM = "11111111-0000-4000-8000-000000000001";

    private static final String ALGORITHM_CBOM = "11111111-0000-4000-8000-000000000002";

    private static final String PROTOCOL_CBOM = "11111111-0000-4000-8000-000000000003";

    private static final String CERTIFICATE_CBOM = "11111111-0000-4000-8000-000000000004";

    private static final String KEY = "22222222-0000-4000-8000-000000000001";

    private static final String ALGORITHM = "22222222-0000-4000-8000-000000000002";

    private static final String PROTOCOL = "22222222-0000-4000-8000-000000000003";

    private static final String CERTIFICATE = "22222222-0000-4000-8000-000000000004";

    private static final String KEY_SOURCE = "33333333-0000-4000-8000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void referrersAreReOfferedAndDocumentsSourcingKeysOrProtocolsAreReQueued() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigrations(connection);
                seedInventory(connection);

                applyMigration(connection);

                assertThat(revisionOf(connection, KEY)).isEqualTo("1");
                assertThat(revisionOf(connection, CERTIFICATE)).isEqualTo("1");
                assertThat(revisionOf(connection, PROTOCOL)).isEqualTo("1");
                assertThat(revisionOf(connection, ALGORITHM))
                        .describedAs("an algorithm's rules did not move")
                        .isEqualTo("0");
                assertThat(syncStateOf(connection, KEY_CBOM)).isEqualTo("PENDING");
                assertThat(syncStateOf(connection, PROTOCOL_CBOM)).isEqualTo("PENDING");
                assertThat(syncStateOf(connection, ALGORITHM_CBOM)).isEqualTo("SYNCED");
                assertThat(syncStateOf(connection, CERTIFICATE_CBOM)).isEqualTo("SYNCED");
                assertThat(queryOne(connection,
                        "SELECT asset_sync_content_refusals::text FROM cbom WHERE uuid = '" + KEY_CBOM + "'"))
                        .isEqualTo("0");
                try (Statement statement = connection.createStatement()) {
                    statement.execute(insertReference("ALGORITHM"));
                    statement.execute(insertReference("PROTOCOL_ALGORITHM"));
                    statement.execute(insertReference("KEY_EXCHANGE_TRANSFORM"));
                    assertThatThrownBy(() -> statement.execute(insertReference("UNKNOWN_KIND")))
                            .isInstanceOf(SQLException.class)
                            .hasMessageContaining("ck_crypto_asset_reference_kind");
                }
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyInventoryMigrations(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(CBOM_STUB);
            for (String resource : INVENTORY_RESOURCES) {
                statement.execute(new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8));
            }
        }
    }

    private void applyMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void seedInventory(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            insertCbom(statement, KEY_CBOM, "key", 3);
            insertCbom(statement, ALGORITHM_CBOM, "algorithm", 0);
            insertCbom(statement, PROTOCOL_CBOM, "protocol", 0);
            insertCbom(statement, CERTIFICATE_CBOM, "certificate", 0);
            insertAsset(statement, KEY, "key-1", "RELATED_CRYPTO_MATERIAL");
            insertAsset(statement, ALGORITHM, "alg-1", "ALGORITHM");
            insertAsset(statement, PROTOCOL, "prt-1", "PROTOCOL");
            insertAsset(statement, CERTIFICATE, "crt-1", "CERTIFICATE");
            insertSource(statement, KEY_SOURCE, KEY, KEY_CBOM);
            insertSource(statement, "33333333-0000-4000-8000-000000000002", ALGORITHM, KEY_CBOM);
            insertSource(statement, "33333333-0000-4000-8000-000000000003", ALGORITHM, ALGORITHM_CBOM);
            insertSource(statement, "33333333-0000-4000-8000-000000000004", PROTOCOL, PROTOCOL_CBOM);
            insertSource(statement, "33333333-0000-4000-8000-000000000005", CERTIFICATE, CERTIFICATE_CBOM);
        }
    }

    private static void insertCbom(Statement statement, String uuid, String serial, int refusals) throws SQLException {
        statement
                .execute(
                        "INSERT INTO cbom (uuid, serial_number, version, asset_sync_state, asset_sync_content_refusals)"
                                + " VALUES ('" + uuid + "', 'urn:uuid:" + serial + "', 1, 'SYNCED', " + refusals + ")");
    }

    private static void insertAsset(Statement statement, String uuid, String identityKey, String assetType)
            throws SQLException {
        statement
                .execute("INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, i_cre, i_upd)"
                        + " VALUES ('" + uuid + "', '" + identityKey + "', 3, '" + assetType + "', now(), now())");
    }

    private static void insertSource(Statement statement, String uuid, String assetUuid, String cbomUuid)
            throws SQLException {
        statement
                .execute("INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)"
                        + " VALUES ('" + uuid + "', '" + assetUuid + "', '" + cbomUuid + "', now(), now())");
    }

    private static String insertReference(String kind) {
        return "INSERT INTO crypto_asset_reference (uuid, source_uuid, kind, ordinal, ref, target_asset_uuid)"
                + " VALUES (gen_random_uuid(), '" + KEY_SOURCE + "', '" + kind + "', 0, 'ref', '" + ALGORITHM + "')";
    }

    private String revisionOf(Connection connection, String uuid) throws SQLException {
        return queryOne(connection, "SELECT input_revision::text FROM crypto_asset WHERE uuid = '" + uuid + "'");
    }

    private String syncStateOf(Connection connection, String uuid) throws SQLException {
        return queryOne(connection, "SELECT asset_sync_state FROM cbom WHERE uuid = '" + uuid + "'");
    }

    private String queryOne(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            assertThat(rows.next()).describedAs(sql).isTrue();
            return rows.getString(1);
        }
    }

    private void dropScratchSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
        } finally {
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }
}
