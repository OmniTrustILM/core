package db.migration;

import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

/**
 * Migration script for the Public Key Changes
 */
public class V202301311500__PublicKeyMigration extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202301311500__PublicKeyMigration.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            createColumn(context);
            addPublicKeyFingerprint(context);
        }
    }

    private void addPublicKeyFingerprint(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT c.uuid, a.content FROM certificate c JOIN certificate_content a ON a.id = c.certificate_content_id")) {
                List<String> commands = new ArrayList<>();
                while (rows.next()) {
                    X509Certificate certificate = CertificateUtil.parseCertificate(rows.getString("content"));
                    String publicKeyFingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()).getBytes(StandardCharsets.UTF_8));
                    commands.add(
                            "update certificate set public_key_fingerprint = '" + publicKeyFingerprint + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                }
                executeCommands(select, commands);
            }
        }
    }


    private void createColumn(Context context) throws Exception {
        String certificate = "ALTER TABLE certificate add column public_key_fingerprint VARCHAR NULL DEFAULT NULL";
        String certificateValidation = "ALTER TABLE certificate ADD status_validation_timestamp timestamp NULL";
        String certificateValidationUpdate = "UPDATE certificate SET status_validation_timestamp = i_cre";
        try (Statement select = context.getConnection().createStatement()) {
            executeCommands(select, List.of(certificate, certificateValidation, certificateValidationUpdate));
        }
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for (String command : commands) {
            select.execute(command);
        }
    }
}