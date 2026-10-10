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

/**
 * Runs {@code V202610101200__crypto_asset_pqc_rule_set_review.sql} over the inventory as the migrations before it leave
 * it, and asserts what deleting the unroutable tier does to the rows around it: the tier's source links and the alias
 * pointing at it go with it, a certificate reference that named it is set to null rather than deleted, and every
 * surviving row is re-offered to the sweep.
 */
class CryptoAssetPqcRuleSetReviewMigrationITest extends BaseSpringBootTest {

    private static final List<String> INVENTORY_RESOURCES = List
            .of("db/migration/V202608271000__crypto_asset_inventory.sql",
                    "db/migration/V202609141000__crypto_asset_curve_membership.sql",
                    "db/migration/V202609291200__crypto_asset_pqc_references.sql");

    private static final String REVIEW_RESOURCE = "db/migration/V202610101200__crypto_asset_pqc_rule_set_review.sql";

    private static final String SCRATCH_SCHEMA = "crypto_asset_pqc_rule_set_review_check";

    /** The inventory and reference migrations alter this table; the columns they read are stubbed. */
    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL,
                "asset_sync_content_refusals" INT NOT NULL DEFAULT 0
            )
            """;

    private static final String CBOM = "11111111-0000-4000-8000-000000000001";

    private static final String UNROUTABLE = "22222222-0000-4000-8000-000000000001";

    private static final String ALGORITHM = "22222222-0000-4000-8000-000000000002";

    private static final String CERTIFICATE = "22222222-0000-4000-8000-000000000003";

    private static final String UNROUTABLE_SOURCE = "33333333-0000-4000-8000-000000000001";

    private static final String CERTIFICATE_SOURCE = "33333333-0000-4000-8000-000000000003";

    @Autowired
    private DataSource dataSource;

    @Test
    void theUnroutableTierGoesWithItsLinksAndEveryOtherRowIsReOffered() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigrations(connection);
                seedInventory(connection);

                applyReviewMigration(connection);

                assertThat(count(connection, "crypto_asset WHERE asset_type = 'UNROUTABLE'")).isZero();
                assertThat(count(connection, "crypto_asset_source WHERE asset_uuid = '" + UNROUTABLE + "'"))
                        .describedAs("the tier's source links cascade")
                        .isZero();
                assertThat(count(connection, "crypto_asset_alias"))
                        .describedAs("an alias pointing at the deleted row cascades")
                        .isZero();
                assertThat(count(connection, "crypto_asset_reference"))
                        .describedAs("a reference that named the deleted row survives")
                        .isEqualTo(1);
                assertThat(queryOne(connection, "SELECT target_asset_uuid::text FROM crypto_asset_reference"))
                        .describedAs("and points at nothing")
                        .isNull();
                assertThat(queryOne(connection,
                        "SELECT input_revision::text FROM crypto_asset WHERE uuid = '" + ALGORITHM + "'"))
                        .describedAs("the algorithm row is re-offered to the sweep")
                        .isEqualTo("1");
                assertThat(queryOne(connection,
                        "SELECT input_revision::text FROM crypto_asset WHERE uuid = '" + CERTIFICATE + "'"))
                        .describedAs("the certificate row is re-offered to the sweep")
                        .isEqualTo("1");
                assertThat(count(connection, "crypto_asset")).isEqualTo(2);
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private void applyInventoryMigrations(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
            statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
            // Only the scratch schema is on the path, so an unqualified name cannot resolve to the entity-generated
            // core schema instead.
            statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
            statement.execute(CBOM_STUB);
            for (String resource : INVENTORY_RESOURCES) {
                statement.execute(new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8));
            }
        }
    }

    private void applyReviewMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(REVIEW_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void seedInventory(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement
                    .execute("INSERT INTO cbom (uuid, serial_number, version) VALUES ('" + CBOM
                            + "', 'urn:uuid:review', 1)");
            insertAsset(statement, UNROUTABLE, "raw-1", "UNROUTABLE");
            insertAsset(statement, ALGORITHM, "alg-1", "ALGORITHM");
            insertAsset(statement, CERTIFICATE, "crt-1", "CERTIFICATE");
            insertSource(statement, UNROUTABLE_SOURCE, UNROUTABLE);
            insertSource(statement, CERTIFICATE_SOURCE, CERTIFICATE);
            statement
                    .execute("INSERT INTO crypto_asset_alias (uuid, absorbed_key, canonical_key, decided_at)"
                            + " VALUES (gen_random_uuid(), 'raw-0', 'raw-1', now())");
            statement
                    .execute(
                            "INSERT INTO crypto_asset_reference (uuid, source_uuid, kind, ordinal, ref, target_asset_uuid)"
                                    + " VALUES (gen_random_uuid(), '" + CERTIFICATE_SOURCE
                                    + "', 'SUBJECT_PUBLIC_KEY', 0, 'key', '" + UNROUTABLE + "')");
        }
    }

    private static void insertAsset(Statement statement, String uuid, String identityKey, String assetType)
            throws SQLException {
        statement
                .execute("INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, i_cre, i_upd)"
                        + " VALUES ('" + uuid + "', '" + identityKey + "', 3, '" + assetType + "', now(), now())");
    }

    private static void insertSource(Statement statement, String uuid, String assetUuid) throws SQLException {
        statement
                .execute("INSERT INTO crypto_asset_source (uuid, asset_uuid, cbom_uuid, first_seen_at, last_seen_at)"
                        + " VALUES ('" + uuid + "', '" + assetUuid + "', '" + CBOM + "', now(), now())");
    }

    private int count(Connection connection, String fromWhere) throws SQLException {
        return Integer.parseInt(queryOne(connection, "SELECT count(*)::text FROM " + fromWhere));
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
            // The connection goes back to a pool shared with the rest of the suite.
            try (Statement reset = connection.createStatement()) {
                reset.execute("RESET search_path");
            }
        }
    }
}
