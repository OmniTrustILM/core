package db.migration;

import com.otilm.core.util.AttributeMigrationUtils;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * Migration script for the Attributes changes.
 * Prerequisite for the successful migration is to have the AttributeDefinition stored in the database.
 * If the relaxed version of the AttributeDefinition is stored, the migration will fail, including missing
 * type, name, uuid, label.
 */
public class V202206151000__AttributeChanges extends BaseJavaMigration {

    private static final String CREDENTIAL_TABLE_NAME = "credential";
    private static final String ACME_TABLE_NAME = "acme_profile";
    private static final String RA_TABLE_NAME = "ra_profile";
    private static final String DISCOVERY_TABLE_NAME = "discovery_history";
    private static final String LOCATION_TABLE_NAME = "location";
    private static final String CERTIFICATE_LOCATION_TABLE_NAME = "certificate_location";

    private static final String ATTRIBUTE_COLUMN_NAME = "attributes";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202206151000__AttributeChanges.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            applyCredentialMigration(context);
            applyRaProfileMigration(context);
            applyDiscoveryHistoryMigration(context);
            applyAcmeProfileMigration(context);
            applyCertificateLocationMigration(context);
            applyLocationMigration(context);
        }
    }

    private void applyCredentialMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT id, attributes FROM credential ORDER BY id")) {
                List<String> migrationCommands = AttributeMigrationUtils.getMigrationCommands(rows, CREDENTIAL_TABLE_NAME, ATTRIBUTE_COLUMN_NAME);
                executeCommands(select, migrationCommands);
            }
        }
    }

    private void applyLocationMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT id, attributes FROM location ORDER BY id")) {
                List<String> migrationCommands = AttributeMigrationUtils.getMigrationCommands(rows, LOCATION_TABLE_NAME, ATTRIBUTE_COLUMN_NAME);
                executeCommands(select, migrationCommands);
            }
        }
    }

    private void applyCertificateLocationMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("select location_id, certificate_id, csr_attributes, push_attributes FROM certificate_location")) {
                List<String> migrationCommands = AttributeMigrationUtils.getMigrationCommands(rows, CERTIFICATE_LOCATION_TABLE_NAME, "push_attributes");
                List<String> csrCommands = AttributeMigrationUtils.getMigrationCommands(rows, CERTIFICATE_LOCATION_TABLE_NAME, "csr_attributes");
                executeCommands(select, migrationCommands);
                executeCommands(select, csrCommands);
            }
        }
    }

    private void applyDiscoveryHistoryMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT id, attributes FROM discovery_history ORDER BY id")) {
                List<String> migrationCommands = AttributeMigrationUtils.getMigrationCommands(rows, DISCOVERY_TABLE_NAME, ATTRIBUTE_COLUMN_NAME);
                executeCommands(select, migrationCommands);
            }
        }
    }

    private void applyRaProfileMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT id, attributes,acme_issue_certificate_attributes,acme_revoke_certificate_attributes FROM ra_profile ORDER BY id")) {
                List<String> raProfileCommands = AttributeMigrationUtils.getMigrationCommands(rows, RA_TABLE_NAME, ATTRIBUTE_COLUMN_NAME);
                List<String> raProfileIssueCommands = AttributeMigrationUtils.getMigrationCommands(rows, RA_TABLE_NAME, "acme_issue_certificate_attributes");
                List<String> raProfileRevokeCommands = AttributeMigrationUtils.getMigrationCommands(rows, RA_TABLE_NAME, "acme_revoke_certificate_attributes");
                executeCommands(select, raProfileCommands);
                executeCommands(select, raProfileIssueCommands);
                executeCommands(select, raProfileRevokeCommands);
            }
        }
    }

    private void applyAcmeProfileMigration(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT id, issue_certificate_attributes, revoke_certificate_attributes FROM acme_profile ORDER BY id")) {
                List<String> acmeProfileIssueCommands = AttributeMigrationUtils.getMigrationCommands(rows, ACME_TABLE_NAME, "issue_certificate_attributes");
                List<String> acmeProfileRevokeCommands = AttributeMigrationUtils.getMigrationCommands(rows, ACME_TABLE_NAME, "revoke_certificate_attributes");
                executeCommands(select, acmeProfileIssueCommands);
                executeCommands(select, acmeProfileRevokeCommands);
            }
        }
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for(String command: commands) {
            select.execute(command);
        }
    }
}