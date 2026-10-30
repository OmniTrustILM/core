package db.migration;


import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;


public class V202408231055__DuplicateCertificates extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202408231055__DuplicateCertificates.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202408231055__DuplicateCertificates.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {

        mergeDuplicateCertificates(context);
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute("ALTER TABLE certificate ADD UNIQUE (fingerprint);");
        }


        deleteDuplicateCrls(context);
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute("ALTER TABLE crl ADD UNIQUE (issuer_dn, serial_number);");
        }


    }

    private void deleteDuplicateCrls(Context context) throws SQLException {
        List<String> uuidsToDelete = new ArrayList<>();
        ResultSet duplicateCrls;
        try (final Statement select = context.getConnection().createStatement()) {
            duplicateCrls = select.executeQuery("SELECT STRING_AGG(uuid::text,',') AS uuids FROM crl  GROUP BY issuer_dn, serial_number HAVING COUNT(*) > 1");

            while (duplicateCrls.next()) {
                List<String> duplicateUuids = new ArrayList<>(List.of(duplicateCrls.getString("uuids").split(",")));
                String crlToKeepUuid = duplicateUuids.getFirst();
                for (String uuid : duplicateUuids) {
                    ResultSet crl;
                    String query = "SELECT ca_certificate_uuid FROM crl WHERE uuid = ?;";
                    try (final PreparedStatement statement = context.getConnection().prepareStatement(query)) {
                        statement.setObject(1, uuid, Types.OTHER);
                        crl = statement.executeQuery();
                        crl.next();
                        if (crl.getString("ca_certificate_uuid") != null) {
                            crlToKeepUuid = uuid;
                            break;
                        }
                    }
                }
                duplicateUuids.remove(crlToKeepUuid);
                uuidsToDelete.addAll(duplicateUuids);
            }
            if (!uuidsToDelete.isEmpty()) {
                String query = "DELETE FROM crl WHERE uuid::text = ANY (string_to_array(?, ','));";
                try (PreparedStatement deleteCrls = context.getConnection().prepareStatement(query)) {
                    deleteCrls.setString(1, String.join(",", uuidsToDelete));
                    deleteCrls.execute();
                }
            }
        }
    }

    private void mergeDuplicateCertificates(Context context) throws SQLException {
        ResultSet duplicateCertificatesGrouped;
        try (final Statement select = context.getConnection().createStatement()) {
            duplicateCertificatesGrouped = select.executeQuery("SELECT STRING_AGG((uuid::text), ',' ORDER BY i_cre ASC) AS uuids FROM certificate WHERE fingerprint IS NOT NULL GROUP BY fingerprint HAVING COUNT(uuid) > 1;");

            String updateGroupsQuery = "UPDATE group_association SET object_uuid = ? WHERE resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')) AND group_uuid " +
                    "NOT IN (SELECT group_uuid FROM group_association WHERE object_uuid = ? );";
            String deleteGroupsQuery = "DELETE FROM group_association WHERE resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')) AND object_uuid != ?;";
            String updateOwnersQuery = "UPDATE owner_association SET object_uuid = ? WHERE uuid = (SELECT oa.uuid FROM owner_association oa JOIN certificate c ON c.uuid = oa.object_uuid " +
                    "WHERE resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')) ORDER BY c.i_cre ASC LIMIT 1) and resource = 'CERTIFICATE';";
            String deleteOwnersQuery = "DELETE FROM owner_association WHERE resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')) AND object_uuid != ?;";
            String updateRaProfileQuery = "UPDATE certificate SET ra_profile_uuid = ( SELECT ra_profile_uuid FROM certificate c WHERE uuid::text = ANY (string_to_array(?, ',')) AND ra_profile_uuid IS NOT NULL ORDER BY c.i_cre ASC LIMIT 1) WHERE uuid = ?;";
            String deleteAttributesQuery = "DELETE FROM attribute_content_2_object WHERE object_type = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')) AND object_uuid != ?;";
            String updateProtocolsQuery = "UPDATE certificate_protocol_association SET certificate_uuid = ? WHERE certificate_uuid:text = ANY (string_to_array(?, ',')) " +
                    "AND protocol_profile_uuid NOT IN (SELECT protocol_profile_uuid FROM certificate_protocol_association " +
                    "WHERE certificate_uuid = ?);";
            String deleteProtocolsQuery = "DELETE FROM certificate_protocol_association WHERE certificate_uuid::text = ANY (string_to_array(?, ',')) AND certificate_uuid != ?;";
            String deleteCrlsQuery = "DELETE FROM crl WHERE ca_certificate_uuid::text = ANY (string_to_array(?, ',')) AND ca_certificate_uuid != ?;";
            String updateScepProfilesQuery = "UPDATE scep_profile SET ca_certificate_uuid = ? WHERE ca_certificate_uuid::text = ANY (string_to_array(?, ','));";
            String deleteHistoryQuery = "DELETE FROM certificate_event_history WHERE certificate_uuid::text = ANY (string_to_array(?, ',')) AND certificate_uuid != ?;";
            String deleteApprovalRecipientsQuery = "DELETE FROM approval_recipient WHERE approval_uuid IN (SELECT uuid FROM approval WHERE object_uuid != ? AND resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ',')));";
            String deleteApprovalsQuery = "DELETE FROM approval WHERE object_uuid != ? AND resource = 'CERTIFICATE' AND object_uuid::text = ANY (string_to_array(?, ','));";
            String updateUserUuidQuery = "UPDATE certificate SET user_uuid = ( SELECT user_uuid FROM certificate c WHERE uuid::text = ANY (string_to_array(?, ',')) " +
                    "AND user_uuid IS NOT NULL ORDER BY c.i_cre ASC LIMIT 1) WHERE uuid = ?;";
            String deleteDuplicatesQuery = "DELETE FROM certificate  WHERE uuid::text = ANY (string_to_array(?, ',')) AND uuid != ?;";
            String deleteCertificateContentsQuery = "DELETE FROM certificate_content WHERE id IN ( SELECT certificate_content_id FROM certificate " +
                    "WHERE uuid::text = ANY (string_to_array(?, ',')) AND uuid != ?);";

            try (PreparedStatement updateGroupsPs = createPreparedStatement(context, updateGroupsQuery);
                 PreparedStatement deleteGroupsPs = createPreparedStatement(context, deleteGroupsQuery);
                 PreparedStatement updateOwnersPs = createPreparedStatement(context, updateOwnersQuery);
                 PreparedStatement deleteOwnersPs = createPreparedStatement(context, deleteOwnersQuery);
                 PreparedStatement updateRaProfilePs = createPreparedStatement(context, updateRaProfileQuery);
                 PreparedStatement deleteAttributesPs = createPreparedStatement(context, deleteAttributesQuery);
                 PreparedStatement updateProtocolsPs = createPreparedStatement(context, updateProtocolsQuery);
                 PreparedStatement deleteProtocolsPs = createPreparedStatement(context, deleteProtocolsQuery);
                 PreparedStatement deleteCrlsPs = createPreparedStatement(context, deleteCrlsQuery);
                 PreparedStatement updateScepProfiles = createPreparedStatement(context, updateScepProfilesQuery);
                 PreparedStatement deleteHistoryPs = createPreparedStatement(context, deleteHistoryQuery);
                 PreparedStatement deleteApprovalRecipientsPs = createPreparedStatement(context, deleteApprovalRecipientsQuery);
                 PreparedStatement deleteApprovalsPs = createPreparedStatement(context, deleteApprovalsQuery);
                 PreparedStatement updateUserUuidPs = createPreparedStatement(context, updateUserUuidQuery);
                 PreparedStatement deleteDuplicatesPs = createPreparedStatement(context, deleteDuplicatesQuery);
                 PreparedStatement deleteCertificateContentsPs = createPreparedStatement(context, deleteCertificateContentsQuery)
            ) {

                while (duplicateCertificatesGrouped.next()) {

                    String duplicateCertificatesGroupedString = duplicateCertificatesGrouped.getString("uuids");


                    List<String> duplicateCertificatesUuids = List.of(duplicateCertificatesGroupedString.split(","));
                    String certificateToKeepUuid = duplicateCertificatesUuids.getFirst();

                    logger.debug("Processing duplicate certificates with UUIDs {}. Keeping certificate with UUID {}.", duplicateCertificatesUuids, certificateToKeepUuid);

                    updateGroupsPs.setObject(1, certificateToKeepUuid, Types.OTHER);
                    updateGroupsPs.setString(2, duplicateCertificatesGroupedString);
                    updateGroupsPs.setObject(3, certificateToKeepUuid, Types.OTHER);
                    updateGroupsPs.addBatch();
                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteGroupsPs);

                    updateOwnersPs.setObject(1, certificateToKeepUuid, Types.OTHER);
                    updateOwnersPs.setString(2, duplicateCertificatesGroupedString);
                    updateOwnersPs.addBatch();
                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteOwnersPs);

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, updateRaProfilePs);

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteAttributesPs);

                    updateProtocolsPs.setObject(1, certificateToKeepUuid, Types.OTHER);
                    updateProtocolsPs.setString(2, duplicateCertificatesGroupedString);
                    updateProtocolsPs.setObject(3, certificateToKeepUuid, Types.OTHER);
                    updateGroupsPs.addBatch();
                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteProtocolsPs);

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteCrlsPs);

                    updateScepProfiles.setObject(1, certificateToKeepUuid, Types.OTHER);
                    updateScepProfiles.setString(2, duplicateCertificatesGroupedString);
                    updateScepProfiles.addBatch();

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteHistoryPs);

                    deleteApprovalRecipientsPs.setObject(1, certificateToKeepUuid, Types.OTHER);
                    deleteApprovalRecipientsPs.setString(2, duplicateCertificatesGroupedString);
                    deleteApprovalRecipientsPs.addBatch();
                    deleteApprovalsPs.setObject(1, certificateToKeepUuid, Types.OTHER);
                    deleteApprovalsPs.setString(2, duplicateCertificatesGroupedString);
                    deleteApprovalsPs.addBatch();

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, updateUserUuidPs);

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteDuplicatesPs);

                    handlePreparedStatement(duplicateCertificatesGroupedString, certificateToKeepUuid, deleteCertificateContentsPs);
                }

                updateGroupsPs.executeBatch();
                deleteGroupsPs.executeBatch();
                logger.debug("Groups of duplicate certificates have been merged.");

                updateOwnersPs.executeBatch();
                deleteOwnersPs.executeBatch();
                logger.debug("Owner has been set for merged certificate.");

                updateRaProfilePs.executeBatch();
                logger.debug("RA Profile has been set for merged certificate.");

                deleteAttributesPs.executeBatch();
                logger.debug("Attributes of duplicate certificates have been deleted.");

                updateProtocolsPs.executeBatch();
                deleteProtocolsPs.executeBatch();
                logger.debug("Protocol associations of duplicate certificates have been merged.");

                deleteCrlsPs.executeBatch();
                logger.debug("CRLs linked to duplicate certificates have been deleted.");

                updateScepProfiles.executeBatch();
                logger.debug("SCEP Profiles have been linked to merged certificates.");

                deleteHistoryPs.executeBatch();
                logger.debug("Certificate event history of duplicate certificates has been deleted.");

                deleteApprovalRecipientsPs.executeBatch();
                deleteApprovalsPs.executeBatch();
                logger.debug("Approvals of duplicate certificates have been deleted.");

                updateUserUuidPs.executeBatch();
                logger.debug("User has been set for merged certificate.");

                deleteDuplicatesPs.executeBatch();
                logger.debug("Duplicate certificates have been deleted.");

                deleteCertificateContentsPs.executeBatch();
                logger.debug("Deleted certificate content of duplicate certificates.");

            }

        }


    }


    private PreparedStatement createPreparedStatement(Context context, String query) throws SQLException {
        return context.getConnection().prepareStatement(query);
    }


    private void handlePreparedStatement(String duplicates, String certificate, PreparedStatement preparedStatement) throws SQLException {
        preparedStatement.setString(1, duplicates);
        preparedStatement.setObject(2, certificate, Types.OTHER);
        preparedStatement.addBatch();
    }

}
