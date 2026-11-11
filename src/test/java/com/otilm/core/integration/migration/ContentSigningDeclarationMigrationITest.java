package com.otilm.core.integration.migration;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import java.nio.charset.StandardCharsets;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

class ContentSigningDeclarationMigrationITest extends BaseMigrationTest {

    private static final String MIGRATION_RESOURCE = "db/migration/V202611111200__content_signing_declaration.sql";

    @Autowired
    private DataSource dataSource;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private SigningProfileRepository profileRepository;
    @Autowired
    private SigningProfileVersionRepository profileVersionRepository;

    @Test
    void createsTheDeclarationTableWhoseRowsGoWithTheirConnector() throws Exception {
        // given
        UUID connectorUuid = insertConnector();
        try (Connection connection = dataSource.getConnection()) {
            simulateOldSchema(connection);

            // when
            runMigration(connection);

            // then
            execute(connection, "INSERT INTO connector_content_signing_declaration VALUES ('%s', '{\"families\": []}')"
                    .formatted(connectorUuid));
            execute(connection, "DELETE FROM connector WHERE uuid = '%s'".formatted(connectorUuid));
            assertThat(count(connection, "SELECT count(*) FROM connector_content_signing_declaration")).isZero();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PADES_FORMATTING", "XADES_FORMATTING", "CADES_FORMATTING", "JADES_FORMATTING"})
    void unifiesTheFormattingInterfaceCode(String familyInterfaceCode) throws Exception {
        // given
        UUID connectorUuid = insertConnector();
        try (Connection connection = dataSource.getConnection()) {
            simulateOldSchema(connection);
            insertInterface(connection, connectorUuid, familyInterfaceCode, List.of());

            // when
            runMigration(connection);

            // then
            assertThat(interfaceCodes(connection, connectorUuid)).containsExactly("CONTENT_SIGNING_FORMATTING");
        }
    }

    @Test
    void keepsAnInterfaceCodeOutsideFormatting() throws Exception {
        // given
        UUID connectorUuid = insertConnector();
        try (Connection connection = dataSource.getConnection()) {
            simulateOldSchema(connection);
            insertInterface(connection, connectorUuid, "AUTHORITY", List.of());

            // when
            runMigration(connection);

            // then
            assertThat(interfaceCodes(connection, connectorUuid)).containsExactly("AUTHORITY");
        }
    }

    @Test
    void removesOnlyTheContentSigningFeatureFlags() throws Exception {
        // given
        UUID connectorUuid = insertConnector();
        try (Connection connection = dataSource.getConnection()) {
            simulateOldSchema(connection);
            insertInterface(connection, connectorUuid, "PADES_FORMATTING",
                    List.of("STATELESS", "CONTENT_SIGNING", "LEVEL_TIMESTAMPED", "LEVEL_LONG_TERM", "LEVEL_ARCHIVAL"));

            // when
            runMigration(connection);

            // then
            assertThat(features(connection, connectorUuid)).containsExactly("STATELESS");
        }
    }

    @Test
    void lowersTheSignatureFamilyToItsCode() throws Exception {
        // given
        UUID versionUuid = insertProfileVersionOfFamily(SignatureFamily.PADES);
        try (Connection connection = dataSource.getConnection()) {
            simulateOldSchema(connection);
            execute(connection, "UPDATE signing_profile_version SET signature_family = 'PADES' WHERE uuid = '%s'"
                    .formatted(versionUuid));

            // when
            runMigration(connection);

            // then
            assertThat(signatureFamily(connection, versionUuid)).isEqualTo("pades");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Gives the tables the shape the migration meets in a deployment: the declaration table absent, and the interface
     * columns as plain text without the enum checks the test schema adds.
     */
    private static void simulateOldSchema(Connection connection) throws SQLException {
        execute(connection, "DROP TABLE IF EXISTS connector_content_signing_declaration");
        execute(connection, """
                DO $$
                DECLARE check_name TEXT;
                BEGIN
                    FOR check_name IN SELECT conname FROM pg_constraint
                            WHERE conrelid = 'connector_interface'::regclass AND contype = 'c' LOOP
                        EXECUTE format('ALTER TABLE connector_interface DROP CONSTRAINT %I', check_name);
                    END LOOP;
                END $$""");
        execute(connection, """
                ALTER TABLE connector_interface
                    ALTER COLUMN interface TYPE TEXT,
                    ALTER COLUMN features TYPE TEXT[]""");
    }

    private static void runMigration(Connection connection) throws Exception {
        String migrationSql = new ClassPathResource(MIGRATION_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        execute(connection, migrationSql);
    }

    private UUID insertConnector() {
        Connector connector = new Connector();
        connector.setName("formatting-" + UUID.randomUUID());
        connector.setVersion(ConnectorVersion.V2);
        return connectorRepository.saveAndFlush(connector).getUuid();
    }

    private UUID insertProfileVersionOfFamily(SignatureFamily family) {
        SigningProfile profile = new SigningProfile();
        profile.setName("profile-" + UUID.randomUUID());
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepository.saveAndFlush(profile);
        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setSigningScheme(SigningScheme.DELEGATED);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setSignatureFamily(family);
        return profileVersionRepository.saveAndFlush(version).getUuid();
    }

    private static void insertInterface(Connection connection, UUID connectorUuid, String code, List<String> features)
            throws SQLException {
        try (PreparedStatement statement = connection
                .prepareStatement(
                        "INSERT INTO connector_interface (uuid, connector_uuid, interface, version, features) VALUES (?, ?, ?, '1', ?)")) {
            statement.setObject(1, UUID.randomUUID());
            statement.setObject(2, connectorUuid);
            statement.setString(3, code);
            statement.setArray(4, connection.createArrayOf("text", features.toArray()));
            statement.executeUpdate();
        }
    }

    private static List<String> interfaceCodes(Connection connection, UUID connectorUuid) throws SQLException {
        return texts(connection,
                "SELECT interface FROM connector_interface WHERE connector_uuid = '%s'".formatted(connectorUuid));
    }

    private static List<String> features(Connection connection, UUID connectorUuid) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet resultSet = statement
                        .executeQuery("SELECT features FROM connector_interface WHERE connector_uuid = '%s'"
                                .formatted(connectorUuid))) {
            resultSet.next();
            Array features = resultSet.getArray(1);
            return List.of((String[]) features.getArray());
        }
    }

    private static String signatureFamily(Connection connection, UUID versionUuid) throws SQLException {
        return texts(connection,
                "SELECT signature_family FROM signing_profile_version WHERE uuid = '%s'".formatted(versionUuid))
                .getFirst();
    }

    private static List<String> texts(Connection connection, String query) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(query)) {
            List<String> texts = new ArrayList<>();
            while (resultSet.next()) {
                texts.add(resultSet.getString(1));
            }
            return texts;
        }
    }

    private static long count(Connection connection, String query) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(query)) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }
}
