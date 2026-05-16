package db.migration;

import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Set;
import java.util.UUID;

/**
 * Back-fills the extended_key_usage_critical column (added in V202604011900)
 * for all pre-existing certificates by parsing their stored DER content and
 * checking whether the Extended Key Usage extension (OID 2.5.29.37) is marked
 * critical.
 */
public class V202604011901__BackfillExtendedKeyUsageCritical extends BaseJavaMigration {

    private static final String EKU_OID = "2.5.29.37";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202604011901__BackfillExtendedKeyUsageCritical.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        // Only process certificates that have EKU data — those without EKU should remain NULL,
        // because criticality is a property of the extension itself, not applicable when absent.
        String selectSql = """
                SELECT c.uuid, cc.content
                FROM certificate c
                JOIN certificate_content cc ON cc.id = c.certificate_content_id
                WHERE c.extended_key_usage IS NOT NULL
                  AND c.extended_key_usage_critical IS NULL
                """;

        String updateSql = "UPDATE certificate SET extended_key_usage_critical = ? WHERE uuid = ?";

        try (Statement select = context.getConnection().createStatement();
             ResultSet rows = select.executeQuery(selectSql);
             PreparedStatement update = context.getConnection().prepareStatement(updateSql)) {

            while (rows.next()) {
                String uuid = rows.getString("uuid");
                String content = rows.getString("content");
                Boolean critical = null;
                try {
                    X509Certificate cert = CertificateUtil.parseCertificate(content);
                    if (cert.getExtendedKeyUsage() != null) {
                        Set<String> criticalOids = cert.getCriticalExtensionOIDs();
                        critical = criticalOids != null && criticalOids.contains(EKU_OID);
                    }
                } catch (Exception e) {
                    // Leave null if the certificate cannot be parsed.
                }
                if (critical != null) {
                    update.setBoolean(1, critical);
                    update.setObject(2, UUID.fromString(uuid));
                    update.addBatch();
                }
            }
            update.executeBatch();
        }
    }
}
