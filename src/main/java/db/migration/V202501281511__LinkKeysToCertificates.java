package db.migration;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.CryptographyUtil;
import com.czertainly.core.util.DatabaseMigration;
import com.czertainly.core.util.KeySizeUtil;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.sql.*;
import java.util.*;

@SuppressWarnings("java:S101")
public class V202501281511__LinkKeysToCertificates extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202501281511__LinkKeysToCertificates.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        prepareDbForUploadedKeys(context);
        linkKeysToCertificates(context);
    }

    private void prepareDbForUploadedKeys(Context context) throws SQLException {
        String alterCkTableQuery = "ALTER TABLE cryptographic_key ALTER COLUMN token_instance_uuid DROP NOT NULL;";
        String alterCkiTableQuery = "ALTER TABLE cryptographic_key_item ALTER COLUMN key_reference_uuid DROP NOT NULL;";
        String addPkColumnToCsrQuery = "ALTER TABLE CERTIFICATE_REQUEST ADD COLUMN key_uuid uuid;";
        String renameKeyUuidColumn = "ALTER TABLE cryptographic_key_item RENAME COLUMN cryptographic_key_uuid TO key_uuid;";
        String renameKeyAlgorithmColumn = "ALTER TABLE cryptographic_key_item RENAME COLUMN cryptographic_algorithm TO key_algorithm;";
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute(alterCkTableQuery);
            statement.execute(alterCkiTableQuery);
            statement.execute(addPkColumnToCsrQuery);
            statement.execute(renameKeyAlgorithmColumn);
            statement.execute(renameKeyUuidColumn);
        }
    }

    private void linkKeysToCertificates(Context context) throws SQLException, NoSuchAlgorithmException {
        String updatePublicKeyQuery = "UPDATE certificate SET key_uuid = ? WHERE uuid = ?";
        String createCkQuery = """
                INSERT INTO cryptographic_key (
                    uuid,
                    i_author,
                    i_cre,
                    i_upd,
                    name
                ) VALUES (
                    ?,
                    ?,
                    NOW(),
                    NOW(),
                    ?
                );
                """;
        String createCkiQuery = """
                INSERT INTO cryptographic_key_item (
                    uuid,
                    name,
                    type,
                    key_uuid,
                    key_algorithm,
                    format,
                    key_data,
                    state,
                    enabled,
                    length,
                    fingerprint,
                    created_at,
                    updated_at
                ) VALUES (
                    ?,
                    ?,
                    'PUBLIC_KEY',
                    ?,
                    ?,
                    ?,
                    ?,
                    'ACTIVE',
                    TRUE,
                    ?,
                    ?,
                    NOW(),
                    NOW()
                );
                
                """;
        Map<String, String> fingeprintToKeyUuidMap = getFingerprinToKeyUuidMap(context);
        try (final Statement select = context.getConnection().createStatement();
             final PreparedStatement updatePublicKeyPs = context.getConnection().prepareStatement(updatePublicKeyQuery);
             final PreparedStatement insertCkPs = context.getConnection().prepareStatement(createCkQuery);
             final PreparedStatement insertCkiPs = context.getConnection().prepareStatement(createCkiQuery)) {
            ResultSet certificatesWithoutKeyLink = select.executeQuery("""
                                            SELECT
                                            c.common_name,
                                            c.i_author,
                                            c.uuid AS certificate_uuid,
                                            cc.content AS certificate_content
                                            FROM certificate c
                                            INNER JOIN certificate_content cc
                                            ON c.certificate_content_id = cc.id
                                            WHERE c.key_uuid IS NULL
                    """);
            while (certificatesWithoutKeyLink.next()) {
                String certificateUuid = certificatesWithoutKeyLink.getString("certificate_uuid");
                PublicKey publicKey;
                try {
                    publicKey = CertificateUtil.parseCertificate(certificatesWithoutKeyLink.getString("certificate_content")).getPublicKey();
                } catch (CertificateException e) {
                    // log debug
                    continue;
                }
                if (publicKey != null) {
                    UUID ckUuid;
                    String publicKeyFingerprint = CertificateUtil.getThumbprint(Base64.getEncoder().encodeToString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
                    if (fingeprintToKeyUuidMap.get(publicKeyFingerprint) != null) {
                        ckUuid = UUID.fromString(fingeprintToKeyUuidMap.get(publicKeyFingerprint));
                    } else {
                        ckUuid = UUID.randomUUID();
                        String keyName = "certKey_" + certificatesWithoutKeyLink.getString("common_name");

                        insertCkPs.setObject(1, ckUuid, Types.OTHER);
                        insertCkPs.setString(2, certificatesWithoutKeyLink.getString("i_author"));
                        insertCkPs.setString(3, keyName);
                        insertCkPs.addBatch();

                        KeyAlgorithm keyAlgorithmEnumValue;
                        try {
                            keyAlgorithmEnumValue = KeyAlgorithm.valueOf(CertificateUtil.getAlgorithmFromProviderName(publicKey.getAlgorithm()));
                        } catch (IllegalArgumentException e) {
                            keyAlgorithmEnumValue = KeyAlgorithm.UNKNOWN;
                        }

                        insertCkiPs.setObject(1, UUID.randomUUID(), Types.OTHER);
                        insertCkiPs.setString(2, keyName);
                        insertCkiPs.setObject(3, ckUuid, Types.OTHER);
                        insertCkiPs.setString(4, keyAlgorithmEnumValue.toString());
                        insertCkiPs.setString(5, CryptographyUtil.getPublicKeyFormat(publicKey.getEncoded()).toString());
                        insertCkiPs.setString(6, Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                        insertCkiPs.setInt(7, KeySizeUtil.getKeyLength(publicKey));
                        insertCkiPs.setString(8, publicKeyFingerprint);
                        insertCkiPs.addBatch();

                        fingeprintToKeyUuidMap.put(publicKeyFingerprint, String.valueOf(ckUuid));
                    }

                    updatePublicKeyPs.setObject(1, ckUuid, Types.OTHER);
                    updatePublicKeyPs.setObject(2, certificateUuid, Types.OTHER);
                    updatePublicKeyPs.addBatch();
                }
            }
            insertCkPs.executeBatch();
            insertCkiPs.executeBatch();
            updatePublicKeyPs.executeBatch();
        }
        // log warn
    }

    private Map<String, String> getFingerprinToKeyUuidMap(Context context) throws SQLException {
        Map<String, String> valueMap = new HashMap<>();
        String query = """
                SELECT ck.uuid,
                cki.fingerprint
                FROM cryptographic_key ck
                INNER JOIN cryptographic_key_item cki
                ON ck.uuid = cki.key_uuid
                """;
        try (final Statement select = context.getConnection().createStatement()) {
            ResultSet resultSet = select.executeQuery(query);
            while (resultSet.next()) {
                String fingerprint = resultSet.getString("fingerprint");
                String uuid = resultSet.getString("uuid");
                valueMap.put(fingerprint, uuid);
            }
        }
        return valueMap;
    }
}
