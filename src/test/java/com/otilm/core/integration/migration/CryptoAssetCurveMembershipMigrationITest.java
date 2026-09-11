package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.PostgresFunctionContributor;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202609101000__crypto_asset_curve_membership.sql} over rows written in the shape the column had before
 * it, and asserts what the conversion did to them.
 *
 * <p>
 * The suite's schema is generated from the entities, so the {@code USING} clause that splits a stored composite runs
 * nowhere else: a conversion that dropped the members, kept the {@code +} inside one element, or turned an absent curve
 * into a one-element array would pass unnoticed. The table is expected to be empty at deployment time -- ingest lands
 * in core#2073 -- but the migration is written to convert data, so the data path is what is asserted.
 */
class CryptoAssetCurveMembershipMigrationITest extends BaseSpringBootTest {

    private static final String INVENTORY_RESOURCE = "db/migration/V202608271000__crypto_asset_inventory.sql";

    private static final String CURVE_RESOURCE = "db/migration/V202609101000__crypto_asset_curve_membership.sql";

    private static final String SCRATCH_SCHEMA = "crypto_asset_curve_migration_check";

    /** The inventory migration alters this table; nothing here reads any other column of it. */
    private static final String CBOM_STUB = """
            CREATE TABLE "cbom" (
                "uuid" UUID PRIMARY KEY,
                "serial_number" TEXT NOT NULL,
                "version" INT NOT NULL
            )
            """;

    @Autowired
    private DataSource dataSource;

    @Test
    void theConversionSplitsACompositeAndLeavesEveryOtherCurveShapeAlone() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigration(connection);
                seedScalarCurves(connection);
                applyCurveMigration(connection);

                assertThat(storedCurve(connection, "single"))
                        .describedAs("a single curve becomes a one-element array")
                        .isEqualTo("{secp256r1}");
                assertThat(storedCurve(connection, "hybrid"))
                        .describedAs("a composite becomes its members, in the order the normalizer sorted them into")
                        .isEqualTo("{other/curve25519,other/curve448}");
                assertThat(storedCurve(connection, "absent"))
                        .describedAs("an absent curve stays SQL NULL rather than becoming an empty array")
                        .isNull();
                assertThat(columnType(connection)).isEqualTo("ARRAY");
                assertThat(curveIndexDefinition(connection))
                        .describedAs("the btree cannot answer array containment")
                        .contains("USING gin");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    /**
     * The index the migration installs has to answer the predicate the platform actually emits, which is the pattern
     * {@link PostgresFunctionContributor#ARRAY_CONTAINS_PATTERN} registers -- rendered here from that constant rather
     * than copied, so a change to the pattern fails this test instead of silently un-indexing the filter.
     *
     * <p>
     * Sequential scans are disabled for the check: on a table this size the planner would pick one on cost alone, and
     * the question is whether an index path exists at all. PostgreSQL has none for {@code scalar = ANY(column)}, which
     * is what makes the pattern's shape part of the migration's correctness rather than a detail of the ORM.
     */
    @Test
    void theCurveIndexAnswersThePredicateTheFilterEmits() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try {
                applyInventoryMigration(connection);
                applyCurveMigration(connection);
                seedManyAssetsForThePlanner(connection);

                assertThat(planFor(connection, membershipPredicate("other/curve25519")))
                        .describedAs("a membership filter reaches the GIN index")
                        .contains("idx_crypto_asset_curve");
            } finally {
                dropScratchSchema(connection);
            }
        }
    }

    private static String membershipPredicate(String curve) {
        return PostgresFunctionContributor.ARRAY_CONTAINS_PATTERN
                .replace("?1", "'" + curve + "'")
                .replace("?2", "curve");
    }

    private void seedManyAssetsForThePlanner(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, curve, i_cre, i_upd)
                    SELECT gen_random_uuid(), 'key-' || g, 2, 'ALGORITHM',
                           CASE WHEN g % 100 = 0 THEN ARRAY['other/curve25519', 'other/curve448']
                                ELSE ARRAY['secp256r1'] END,
                           now(), now()
                    FROM generate_series(1, 2000) AS g
                    """);
            statement.execute("ANALYZE crypto_asset");
        }
    }

    private String planFor(Connection connection, String predicate) throws SQLException {
        StringBuilder plan = new StringBuilder();
        // The connection is in autocommit, where SET LOCAL is a no-op; the session setting is reset with the
        // search_path when the scratch schema is dropped, before the connection returns to the shared pool.
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET enable_seqscan = off");
            try (ResultSet rows = statement.executeQuery("EXPLAIN SELECT uuid FROM crypto_asset WHERE " + predicate)) {
                while (rows.next()) {
                    plan.append(rows.getString(1)).append('\n');
                }
            }
        }
        return plan.toString();
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

    private void applyCurveMigration(Connection connection) throws Exception {
        String migration = new ClassPathResource(CURVE_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        try (Statement statement = connection.createStatement()) {
            statement.execute(migration);
        }
    }

    private void seedScalarCurves(Connection connection) throws SQLException {
        insertAsset(connection, "single", "'secp256r1'");
        insertAsset(connection, "hybrid", "'other/curve25519+other/curve448'");
        insertAsset(connection, "absent", "NULL");
    }

    private void insertAsset(Connection connection, String identityKey, String curveLiteral) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO crypto_asset (uuid, identity_key, ruleset_version, asset_type, curve, i_cre, i_upd)
                    VALUES (gen_random_uuid(), '%s', 2, 'ALGORITHM', %s, now(), now())
                    """.formatted(identityKey, curveLiteral));
        }
    }

    private String storedCurve(Connection connection, String identityKey) throws SQLException {
        return queryOne(connection,
                "SELECT curve::TEXT FROM crypto_asset WHERE identity_key = '%s'".formatted(identityKey));
    }

    private String columnType(Connection connection) throws SQLException {
        return queryOne(connection, """
                SELECT data_type FROM information_schema.columns
                WHERE table_schema = '%s' AND table_name = 'crypto_asset' AND column_name = 'curve'
                """.formatted(SCRATCH_SCHEMA));
    }

    private String curveIndexDefinition(Connection connection) throws SQLException {
        return queryOne(connection, """
                SELECT indexdef FROM pg_indexes
                WHERE schemaname = '%s' AND indexname = 'idx_crypto_asset_curve'
                """.formatted(SCRATCH_SCHEMA));
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
                reset.execute("RESET enable_seqscan");
            }
        }
    }
}
