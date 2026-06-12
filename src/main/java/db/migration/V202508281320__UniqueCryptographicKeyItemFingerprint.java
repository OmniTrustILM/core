package db.migration;

import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;

@SuppressWarnings("java:S101")
public class V202508281320__UniqueCryptographicKeyItemFingerprint extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202508281320__UniqueCryptographicKeyItemFingerprint.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202508281320__UniqueCryptographicKeyItemFingerprint.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {

        try (Statement selectKeyItems = context.getConnection().createStatement();
             PreparedStatement selectKey = context.getConnection().prepareStatement(
                     "SELECT ck.uuid FROM cryptographic_key ck " +
                             "JOIN cryptographic_key_item cki ON ck.uuid = cki.key_uuid " +
                             "WHERE cki.uuid = ANY (?)"
             );
             PreparedStatement selectKeyItemsFromPair = context.getConnection().prepareStatement(
                     "SELECT uuid FROM cryptographic_key_item WHERE key_uuid = ANY (?)"
             );
             PreparedStatement updateCertKeys = context.getConnection().prepareStatement(
                     "UPDATE certificate SET key_uuid = ? WHERE key_uuid = ANY (?)"
             );
             PreparedStatement updateCertAltKeys = context.getConnection().prepareStatement(
                     "UPDATE certificate SET alt_key_uuid = ? WHERE alt_key_uuid = ANY (?)"
             );
             PreparedStatement updateCertReqKeys = context.getConnection().prepareStatement(
                     "UPDATE certificate_request SET key_uuid = ? WHERE key_uuid = ANY (?)"
             );
             PreparedStatement updateCertReqAltKeys = context.getConnection().prepareStatement(
                     "UPDATE certificate_request SET alt_key_uuid = ? WHERE alt_key_uuid = ANY (?)"
             );
             PreparedStatement deleteCki = context.getConnection().prepareStatement(
                     "DELETE FROM cryptographic_key_item WHERE uuid = ANY (?)"
             );
             PreparedStatement deleteCk = context.getConnection().prepareStatement(
                     "DELETE FROM cryptographic_key WHERE uuid = ANY (?)"
             )
        ) {
            ResultSet duplicateKeysNotCustom = selectKeyItems.executeQuery(
                    "SELECT STRING_AGG(uuid::text, ',' ORDER BY created_at) AS uuids " +
                            "FROM cryptographic_key_item WHERE format != 'CUSTOM' " +
                            "GROUP BY fingerprint HAVING COUNT(uuid) > 1"
            );

            Set<String> ckiUuidToDelete = new HashSet<>();
            Set<String> ckUuidToDelete = new HashSet<>();

            int duplicatesCount = 0;

            while (duplicateKeysNotCustom.next()) {
                duplicatesCount++;
                String duplicateKeysNotCustomString = duplicateKeysNotCustom.getString("uuids");
                List<String> duplicateCertificateContentsIds =
                        new ArrayList<>(Arrays.asList(duplicateKeysNotCustomString.split(",")));

                // ---- fetch key UUIDs
                Array sqlArrayCkiUuids = context.getConnection().createArrayOf("UUID", duplicateCertificateContentsIds.toArray());
                selectKey.setArray(1, sqlArrayCkiUuids);
                ResultSet keys = selectKey.executeQuery();

                List<String> keyUuids = new ArrayList<>();
                while (keys.next()) {
                    keyUuids.add(keys.getString("uuid"));
                }
                if (keyUuids.isEmpty()) continue;

                UUID firstKeyUuid = UUID.fromString(keyUuids.getFirst());
                keyUuids.removeFirst();

                if (!keyUuids.isEmpty()) {
                    Array sqlKeyArray = context.getConnection().createArrayOf("UUID", keyUuids.toArray());

                    updateCertKeys.setObject(1, firstKeyUuid);
                    updateCertKeys.setArray(2, sqlKeyArray);
                    updateCertKeys.addBatch();

                    updateCertAltKeys.setObject(1, firstKeyUuid);
                    updateCertAltKeys.setArray(2, sqlKeyArray);
                    updateCertAltKeys.addBatch();

                    updateCertReqKeys.setObject(1, firstKeyUuid);
                    updateCertReqKeys.setArray(2, sqlKeyArray);
                    updateCertReqKeys.addBatch();

                    updateCertReqAltKeys.setObject(1, firstKeyUuid);
                    updateCertReqAltKeys.setArray(2, sqlKeyArray);
                    updateCertReqAltKeys.addBatch();

                    if (!duplicateCertificateContentsIds.isEmpty()) {
                        duplicateCertificateContentsIds.removeFirst();
                    }

                    // fetch all cki linked to the duplicate keys
                    selectKeyItemsFromPair.setArray(1, sqlKeyArray);
                    ResultSet keysFromPair = selectKeyItemsFromPair.executeQuery();
                    ckiUuidToDelete.addAll(duplicateCertificateContentsIds);
                    while (keysFromPair.next()) {
                        ckiUuidToDelete.add(keysFromPair.getString("uuid"));
                    }


                    // mark duplicates for deletion
                    ckUuidToDelete.addAll(keyUuids);
                }
            }

            logger.debug("Processed {} duplicate cryptographic key fingerprints.", duplicatesCount);

            // execute batched updates
            updateCertKeys.executeBatch();
            updateCertAltKeys.executeBatch();
            updateCertReqKeys.executeBatch();
            updateCertReqAltKeys.executeBatch();

            // execute deletes
            if (!ckiUuidToDelete.isEmpty()) {
                deleteCki.setArray(1, context.getConnection().createArrayOf("UUID", ckiUuidToDelete.toArray()));
                deleteCki.executeUpdate();
            }
            logger.debug("Deleted {} cryptographic key items having duplicate fingerprints.", ckiUuidToDelete.size());

            if (!ckUuidToDelete.isEmpty()) {
                deleteCk.setArray(1, context.getConnection().createArrayOf("UUID", ckUuidToDelete.toArray()));
                deleteCk.executeUpdate();
            }
            logger.debug("Deleted {} cryptographic keys with key items having duplicate fingerprints.", ckUuidToDelete.size());

            selectKeyItems.execute("UPDATE cryptographic_key_item SET fingerprint = NULL WHERE format = 'CUSTOM'");
            selectKeyItems.execute("ALTER TABLE cryptographic_key_item ADD UNIQUE (fingerprint);");
        }
    }

}
