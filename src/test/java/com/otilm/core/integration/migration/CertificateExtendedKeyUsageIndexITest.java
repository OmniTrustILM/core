package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.PostgresFunctionContributor;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateExtendedKeyUsageIndexITest extends BaseSpringBootTest {

    private static final String SCHEMA = "certificate_eku_index_check";
    private static final String INDEX = "idx_certificate_extended_key_usage_gin";
    private static final String MIGRATION = "db/migration/V202609241000__certificate_eku_membership_index.sql";

    @Autowired
    private DataSource dataSource;

    @Test
    void membershipPredicateCanUseTheInventoryIndex() throws Exception {
        ClassPathResource resource = new ClassPathResource(MIGRATION);
        assertThat(resource.exists()).isTrue();

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(true);
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCHEMA);
                statement.execute("SET search_path TO " + SCHEMA);
                statement.execute("CREATE TABLE certificate (id INTEGER, extended_key_usage TEXT)");
                statement.execute("""
                        INSERT INTO certificate (id, extended_key_usage)
                        SELECT g, CASE WHEN g % 100 = 0 THEN '["1.3.6.1.5.5.7.3.1"]'
                                       ELSE '["1.3.6.1.5.5.7.3.2"]' END
                        FROM generate_series(1, 2000) AS g
                        """);
                statement.execute(resource.getContentAsString(StandardCharsets.UTF_8));
                statement.execute("ANALYZE certificate");
                statement.execute("SET enable_seqscan = off");

                String predicate = PostgresFunctionContributor.JSON_TEXT_ARRAY_CONTAINS_PATTERN
                        .replace("?1", "extended_key_usage")
                        .replace("?2", "'[\"1.3.6.1.5.5.7.3.1\"]'");
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
