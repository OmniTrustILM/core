package db.migration;


import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.List;

@SuppressWarnings("java:S101")
public class V202501281641__DuplicateCertificateContents extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202501281641__DuplicateCertificateContents.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202501281641__DuplicateCertificateContents.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        mergeDuplicateCertificateContents(context);
    }


    private void mergeDuplicateCertificateContents(Context context) throws SQLException {
        ResultSet duplicateCertificateContentsGrouped;
        try (final Statement select = context.getConnection().createStatement()) {
            duplicateCertificateContentsGrouped = select.executeQuery("SELECT STRING_AGG((id::text), ',') AS ids FROM certificate_content GROUP BY fingerprint HAVING COUNT(id) > 1;");

            String updateCertificatesQuery = "UPDATE certificate SET certificate_content_id = ? WHERE certificate_content_id::text = ANY (string_to_array(?, ','));";
            String updateDiscoveryCertificateQuery = "UPDATE discovery_certificate SET certificate_content_id = ? WHERE certificate_content_id::text = ANY (string_to_array(?, ','));";
            String deleteDuplicatesQuery = "DELETE FROM certificate_content WHERE id::text = ANY (string_to_array(?, ',')) AND id != ?;";

            try (PreparedStatement updateCertificatesPs = createPreparedStatement(context, updateCertificatesQuery);
                 PreparedStatement updateDiscoveryCertificatesPs = createPreparedStatement(context, updateDiscoveryCertificateQuery);
                 PreparedStatement deleteDuplicatesPs = createPreparedStatement(context, deleteDuplicatesQuery);
            ) {
                while (duplicateCertificateContentsGrouped.next()) {

                    String duplicateCertificateContentsGroupedString = duplicateCertificateContentsGrouped.getString("ids");

                    List<String> duplicateCertificateContentsIds = List.of(duplicateCertificateContentsGroupedString.split(","));
                    int certificateContentToKeepId = Integer.parseInt(duplicateCertificateContentsIds.getFirst());

                    logger.debug("Processing duplicate certificate contents with IDs {}. Keeping certificate content with ID {}.", duplicateCertificateContentsIds, certificateContentToKeepId);

                    updateCertificatesPs.setInt(1, certificateContentToKeepId);
                    updateCertificatesPs.setString(2, duplicateCertificateContentsGroupedString);
                    updateCertificatesPs.addBatch();

                    updateDiscoveryCertificatesPs.setInt(1, certificateContentToKeepId);
                    updateDiscoveryCertificatesPs.setString(2, duplicateCertificateContentsGroupedString);
                    updateDiscoveryCertificatesPs.addBatch();

                    deleteDuplicatesPs.setString(1, duplicateCertificateContentsGroupedString);
                    deleteDuplicatesPs.setInt(2, certificateContentToKeepId);
                    deleteDuplicatesPs.addBatch();
                }

                updateCertificatesPs.executeBatch();
                updateDiscoveryCertificatesPs.executeBatch();
                deleteDuplicatesPs.executeBatch();
            }

        }
    }


    private PreparedStatement createPreparedStatement(Context context, String query) throws SQLException {
        return context.getConnection().prepareStatement(query);
    }

}
