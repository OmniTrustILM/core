package com.otilm.core.integration.migration;

import com.otilm.core.util.BaseSpringBootTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@code V202610291200__compliance_profile_association_drop_orphaned.sql} in a scratch schema and asserts it
 * removes the associations whose object no longer exists, and those of certificate requests no certificate refers to,
 * keeps those whose object does, and leaves the associations of other resources alone.
 */
class ComplianceProfileAssociationDropOrphanedMigrationITest extends BaseSpringBootTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202610291200__compliance_profile_association_drop_orphaned.sql";
    private static final String SCRATCH_SCHEMA = "compliance_profile_association_drop_orphaned_migration_check";
    private static final Map<String, String> TABLES_BY_RESOURCE = Map
            .of("RA_PROFILE", "ra_profile", "TOKEN_PROFILE", "token_profile", "VAULT_PROFILE", "vault_profile",
                    "CERTIFICATE", "certificate", "CRYPTOGRAPHIC_KEY", "cryptographic_key", "CRYPTOGRAPHIC_KEY_ITEM",
                    "cryptographic_key_item", "SECRET", "secret");
    private static final String COMPLIANCE_PROFILE = "10000000-0000-0000-0000-000000000001";
    private static final String OTHER_RESOURCE_ASSOCIATION = "20000000-0000-0000-0000-000000000001";

    @Autowired
    private DataSource dataSource;

    @Test
    void associationsOfMissingObjectsAreRemoved() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                statement.execute("CREATE SCHEMA " + SCRATCH_SCHEMA);
                statement.execute("SET search_path TO " + SCRATCH_SCHEMA);
                statement.execute("""
                        CREATE TABLE "compliance_profile_association" (
                            "uuid" UUID PRIMARY KEY,
                            "compliance_profile_uuid" UUID NOT NULL,
                            "resource" VARCHAR NOT NULL,
                            "object_uuid" UUID NOT NULL
                        )
                        """);

                List<String> liveAssociations = new ArrayList<>();
                for (Map.Entry<String, String> resourceTable : TABLES_BY_RESOURCE.entrySet()) {
                    String existingObject = UUID.randomUUID().toString();
                    statement.execute("CREATE TABLE \"" + resourceTable.getValue() + "\" (\"uuid\" UUID PRIMARY KEY)");
                    statement
                            .execute("INSERT INTO \"" + resourceTable.getValue() + "\" VALUES ('" + existingObject
                                    + "')");
                    liveAssociations.add(insertAssociation(statement, resourceTable.getKey(), existingObject));
                    insertAssociation(statement, resourceTable.getKey(), UUID.randomUUID().toString());
                }
                statement.execute("ALTER TABLE \"certificate\" ADD COLUMN \"certificate_request_uuid\" UUID");
                String issuedRequest = UUID.randomUUID().toString();
                statement.execute("INSERT INTO \"certificate\" VALUES (gen_random_uuid(), '" + issuedRequest + "')");
                liveAssociations.add(insertAssociation(statement, "CERTIFICATE_REQUEST", issuedRequest));
                insertAssociation(statement, "CERTIFICATE_REQUEST", UUID.randomUUID().toString());
                statement
                        .execute("INSERT INTO compliance_profile_association VALUES ('" + OTHER_RESOURCE_ASSOCIATION
                                + "', '" + COMPLIANCE_PROFILE + "', 'AUTHORITY', gen_random_uuid())");
                liveAssociations.add(OTHER_RESOURCE_ASSOCIATION);

                String migration = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
                statement.execute(migration);
                assertThat(remainingAssociations(statement)).containsExactlyInAnyOrderElementsOf(liveAssociations);

                statement.execute(migration);
                assertThat(remainingAssociations(statement)).containsExactlyInAnyOrderElementsOf(liveAssociations);
            } finally {
                try (Statement statement = connection.createStatement()) {
                    // The connection goes back to a pool shared with the rest of the suite: the session's search_path
                    // must not point at the schema this drops.
                    statement.execute("RESET search_path");
                    statement.execute("DROP SCHEMA IF EXISTS " + SCRATCH_SCHEMA + " CASCADE");
                }
            }
        }
    }

    private static String insertAssociation(Statement statement, String resource, String objectUuid) throws Exception {
        String associationUuid = UUID.randomUUID().toString();
        statement
                .execute("INSERT INTO compliance_profile_association VALUES ('" + associationUuid + "', '"
                        + COMPLIANCE_PROFILE + "', '" + resource + "', '" + objectUuid + "')");
        return associationUuid;
    }

    private static List<String> remainingAssociations(Statement statement) throws Exception {
        List<String> remaining = new ArrayList<>();
        try (ResultSet rows = statement.executeQuery("SELECT uuid::text FROM compliance_profile_association")) {
            while (rows.next()) {
                remaining.add(rows.getString(1));
            }
        }
        return remaining;
    }
}
