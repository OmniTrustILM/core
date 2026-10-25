package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.PostgresFunctionContributor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateListColumnsMigrationITest extends BaseSpringBootTest {

    private static final String SCHEMA = "certificate_list_columns_check";
    private static final String INDEX = "idx_certificate_extended_key_usage";
    private static final String MIGRATION = "db/migration/V202610151200__certificate_list_columns_text_array.sql";

    @Autowired
    private DataSource dataSource;

    @TempDir
    private Path migrationDirectory;

    @Test
    void migrationConvertsJsonTextToArraysAndIndexServesMembership() throws Exception {
        ClassPathResource resource = new ClassPathResource(MIGRATION);
        assertThat(resource.exists()).isTrue();
        Files
                .writeString(migrationDirectory.resolve(resource.getFilename()),
                        resource.getContentAsString(StandardCharsets.UTF_8));
        assertThat(new ClassPathResource(MIGRATION + ".conf").exists()).isFalse();

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCHEMA);
                statement.execute("SET search_path TO " + SCHEMA);
                statement.execute("""
                        CREATE TABLE certificate (id INTEGER, extended_key_usage TEXT, qc_type TEXT,
                                                  qc_cc_legislation TEXT)
                        """);
                // Every form the columns were written in: arrays, the text null of older builds, [] and SQL NULL.
                statement.execute("""
                        INSERT INTO certificate (id, extended_key_usage, qc_type, qc_cc_legislation) VALUES
                            (1, '["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"]', '["ESIGN","ESEAL"]', '["CZ"]'),
                            (2, 'null', 'null', 'null'),
                            (3, '[]', '[]', '[]'),
                            (4, NULL, NULL, NULL)
                        """);
                statement.execute("""
                        INSERT INTO certificate (id, extended_key_usage)
                        SELECT g, CASE WHEN g % 100 = 0 THEN '["1.3.6.1.5.5.7.3.8"]'
                                       ELSE '["1.3.6.1.5.5.7.3.2"]' END
                        FROM generate_series(10, 2000) AS g
                        """);
                Flyway
                        .configure()
                        .dataSource(dataSource)
                        .schemas(SCHEMA)
                        .defaultSchema(SCHEMA)
                        .baselineOnMigrate(true)
                        .baselineVersion("0")
                        .locations("filesystem:" + migrationDirectory.toAbsolutePath().toString().replace('\\', '/'))
                        .load()
                        .migrate();

                Map<Integer, String> converted = new LinkedHashMap<>();
                try (ResultSet rows = statement.executeQuery("""
                        SELECT id, extended_key_usage::text || '|' || qc_type::text || '|' || qc_cc_legislation::text,
                               extended_key_usage IS NULL AND qc_type IS NULL AND qc_cc_legislation IS NULL
                        FROM certificate WHERE id < 10 ORDER BY id
                        """)) {
                    while (rows.next()) {
                        converted.put(rows.getInt(1), rows.getBoolean(3) ? "absent" : rows.getString(2));
                    }
                }
                assertThat(converted)
                        .containsExactly(Map.entry(1, "{1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2}|{ESIGN,ESEAL}|{CZ}"),
                                Map.entry(2, "absent"), Map.entry(3, "absent"), Map.entry(4, "absent"));

                try (ResultSet rows = statement.executeQuery("""
                        SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE n.nspname = current_schema() AND p.proname = 'json_text_array_to_text_array'
                        """)) {
                    rows.next();
                    assertThat(rows.getInt(1)).as("conversion function is dropped").isZero();
                }

                statement.execute("ANALYZE certificate");
                statement.execute("SET enable_seqscan = off");
                String predicate = PostgresFunctionContributor.ARRAY_CONTAINS_PATTERN
                        .replace("?1", "'1.3.6.1.5.5.7.3.8'")
                        .replace("?2", "extended_key_usage");
                StringBuilder plan = new StringBuilder();
                try (ResultSet rows = statement.executeQuery("EXPLAIN SELECT id FROM certificate WHERE " + predicate)) {
                    while (rows.next()) {
                        plan.append(rows.getString(1)).append('\n');
                    }
                }
                assertThat(plan.toString()).contains(INDEX);
            } finally {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("RESET enable_seqscan");
                    statement.execute("RESET search_path");
                    statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                }
            }
        }
    }
}
