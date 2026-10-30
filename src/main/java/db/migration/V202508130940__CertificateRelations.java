package db.migration;

import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DatabaseMigration;
import org.bouncycastle.asn1.x509.Extension;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Base64;
import java.util.Objects;

@SuppressWarnings("java:S101")
public class V202508130940__CertificateRelations extends BaseJavaMigration {

    public static final String KEY_UUID = "key_uuid";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202508130940__CertificateRelations.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {

        migrateAltKeyFingerprint(context);
        String updateCertificateRelations = """
                INSERT INTO certificate_relation
                (successor_certificate_uuid, predecessor_certificate_uuid, relation_type, created_at)
                VALUES
                (?, ?, ?, NOW())
                """;
        try (final Statement statement = context.getConnection().createStatement();
             final PreparedStatement preparedStatement = context.getConnection().prepareStatement(updateCertificateRelations)) {
            String createRelationTable = """
                    CREATE TABLE certificate_relation (
                             successor_certificate_uuid UUID NOT NULL,
                             predecessor_certificate_uuid UUID NOT NULL,
                             relation_type TEXT,
                             created_at TIMESTAMP WITH TIME ZONE,
                    
                             CONSTRAINT pk_certificate_relation PRIMARY KEY (successor_certificate_uuid, predecessor_certificate_uuid),
                    
                             CONSTRAINT fk_certificate_relation_successor_certificate
                                 FOREIGN KEY (successor_certificate_uuid)
                                 REFERENCES certificate (uuid)
                                 ON UPDATE CASCADE
                                 ON DELETE CASCADE,
                    
                             CONSTRAINT fk_certificate_relation_predecessor_certificate
                                 FOREIGN KEY (predecessor_certificate_uuid)
                                 REFERENCES certificate (uuid)
                                 ON UPDATE CASCADE
                                 ON DELETE CASCADE
                             )
                    """;
            statement.execute(createRelationTable);

            ResultSet certificates = statement.executeQuery("""
                    SELECT uuid, state, source_certificate_uuid, public_key_fingerprint, alt_key_fingerprint
                        FROM certificate WHERE source_certificate_uuid IS NOT NULL
                    """);

            while (certificates.next()) {
                String sourceCertificateUuid = certificates.getString("source_certificate_uuid");
                CertificateState state = CertificateState.valueOf(certificates.getString("state"));
                if (state != CertificateState.REJECTED && state != CertificateState.FAILED) {
                    String relationType = CertificateRelationType.PENDING.name();
                    try (final PreparedStatement selectSourceCertificate = context.getConnection().prepareStatement(
                            "SELECT public_key_fingerprint, alt_key_fingerprint FROM certificate WHERE uuid = ?")) {
                        selectSourceCertificate.setObject(1, sourceCertificateUuid, Types.OTHER);
                        ResultSet sourceCertificate = selectSourceCertificate.executeQuery();
                        if (sourceCertificate.next()) {
                            createCertificateRelation(state, certificates, sourceCertificate, relationType, preparedStatement, sourceCertificateUuid);
                        }
                    }
                }
            }

            preparedStatement.executeBatch();
            statement.execute("ALTER TABLE certificate DROP COLUMN source_certificate_uuid");
        }
    }

    private static void createCertificateRelation(CertificateState state, ResultSet certificates, ResultSet sourceCertificate, String relationType, PreparedStatement preparedStatement, String sourceCertificateUuid) throws SQLException {
        if (state == CertificateState.ISSUED) {
            if (Objects.equals(certificates.getString("public_key_fingerprint"), sourceCertificate.getObject("public_key_fingerprint"))
                    && Objects.equals(certificates.getString("alt_key_fingerprint"), sourceCertificate.getObject("alt_key_fingerprint")))
                relationType = CertificateRelationType.RENEWAL.name();
            else relationType = CertificateRelationType.REKEY.name();
        }
        preparedStatement.setObject(1, certificates.getObject("uuid"), Types.OTHER);
        preparedStatement.setObject(2, sourceCertificateUuid, Types.OTHER);
        preparedStatement.setObject(3, relationType);

        preparedStatement.addBatch();
    }

    private void migrateAltKeyFingerprint(Context context) throws SQLException {
        String addAltKeyFingerprintColumn = "ALTER TABLE certificate ADD COLUMN alt_key_fingerprint TEXT";
        String updateAltKeyFingerprint = "UPDATE certificate SET alt_key_fingerprint = ? WHERE uuid = ?";
        try (final Statement statement = context.getConnection().createStatement();
             PreparedStatement preparedStatement = context.getConnection().prepareStatement(updateAltKeyFingerprint)) {
            statement.execute(addAltKeyFingerprintColumn);
            ResultSet certificates = statement.executeQuery("SELECT c.uuid, cc.content FROM certificate c JOIN certificate_content cc ON c.certificate_content_id = cc.id WHERE c.hybrid_certificate = TRUE");
            while (certificates.next()) {
                String content = certificates.getString("content");
                String altPublicKeyFingerprint;
                try {
                    X509Certificate x509Certificate = CertificateUtil.getX509Certificate(content);
                    PublicKey altKey = CertificateUtil.getAltPublicKey(x509Certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId()));
                    altPublicKeyFingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(altKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException e) {
                    continue;
                }
                preparedStatement.setString(1, altPublicKeyFingerprint);
                preparedStatement.setObject(2, certificates.getObject("uuid"), Types.OTHER);
                preparedStatement.addBatch();
            }
            preparedStatement.executeBatch();
        }
    }

}
