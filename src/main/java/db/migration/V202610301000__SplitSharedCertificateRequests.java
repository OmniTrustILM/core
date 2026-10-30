package db.migration;

import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Gives every certificate a certificate request of its own. Earlier releases stored an identical CSR once and pointed
 * every certificate submitted with it at that row, so the compliance result kept on the row was overwritten by
 * whichever RA profile checked it last, and that result gated the issuance of all of them.
 * <p>
 * The oldest certificate keeps the row, and every other certificate gets a copy of it. A copy keeps every column of the
 * row, the stored compliance result included: the row does not record which certificate that result was computed for,
 * so each certificate shows what it showed before until it is checked again. The result gates nothing any more: a
 * request is checked for issuance only when it is submitted. The attribute values submitted with the request are mapped
 * to each copy as well. Compliance profile associations name the request itself, so they stay with the row the oldest
 * certificate keeps.
 * <p>
 * The columns are read from the catalog, so a copy carries every column the table has when this runs. A certificate
 * the previous release points at a stored request, while this runs or after it during a rolling update, shares that
 * request from then on.
 */
// Flyway requires the V<timestamp>__Name class name to resolve the migration version; it cannot match S101's
// class-name pattern.
@SuppressWarnings("java:S101")
public class V202610301000__SplitSharedCertificateRequests extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202610301000__SplitSharedCertificateRequests.class);

    private static final String DROP_SPLIT = "DROP TABLE IF EXISTS certificate_request_split";

    private static final String CREATE_SPLIT = """
            CREATE TEMP TABLE certificate_request_split AS
            SELECT ranked.uuid AS certificate_uuid, ranked.certificate_request_uuid AS request_uuid,
                   gen_random_uuid() AS copy_uuid
              FROM (SELECT uuid, certificate_request_uuid,
                           row_number() OVER (PARTITION BY certificate_request_uuid ORDER BY i_cre, uuid) AS position
                      FROM certificate
                     WHERE certificate_request_uuid IS NOT NULL) ranked
             WHERE ranked.position > 1
            """;

    private static final String SELECT_COLUMNS = """
            SELECT column_name
              FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = ? AND column_name::TEXT <> ALL (?)
             ORDER BY ordinal_position
            """;

    private static final String COPY_REQUESTS = """
            INSERT INTO certificate_request (uuid, %s)
            SELECT split.copy_uuid, %s
              FROM certificate_request_split split
              JOIN certificate_request request ON request.uuid = split.request_uuid
            """;

    private static final String COPY_ATTRIBUTE_MAPPINGS = """
            INSERT INTO attribute_content_2_object (uuid, object_uuid, %s)
            SELECT gen_random_uuid(), split.copy_uuid, %s
              FROM certificate_request_split split
              JOIN attribute_content_2_object mapping
                ON mapping.object_type = 'CERTIFICATE_REQUEST' AND mapping.object_uuid = split.request_uuid
            """;

    private static final String POINT_CERTIFICATES_AT_COPIES = """
            UPDATE certificate
               SET certificate_request_uuid = split.copy_uuid
              FROM certificate_request_split split
             WHERE certificate.uuid = split.certificate_uuid
            """;

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202610301000__SplitSharedCertificateRequests.getChecksum();
    }

    @Override
    public void migrate(Context context) throws SQLException {
        Connection connection = context.getConnection();
        List<String> requestColumns = columns(connection, "certificate_request", "uuid");
        List<String> mappingColumns = columns(connection, "attribute_content_2_object", "uuid", "object_uuid");
        try (Statement statement = connection.createStatement()) {
            statement.execute(DROP_SPLIT);
            statement.execute(CREATE_SPLIT);
            int copies = statement.executeUpdate(COPY_REQUESTS.formatted(String.join(", ", requestColumns),
                    qualified("request", requestColumns)));
            int mappings = statement.executeUpdate(COPY_ATTRIBUTE_MAPPINGS.formatted(String.join(", ", mappingColumns),
                    qualified("mapping", mappingColumns)));
            statement.executeUpdate(POINT_CERTIFICATES_AT_COPIES);
            statement.execute(DROP_SPLIT);
            logger.info("Gave {} certificates a copy of the certificate request they shared, with {} attribute values",
                    copies, mappings);
        }
    }

    private static List<String> columns(Connection connection, String table, String... excluded) throws SQLException {
        List<String> columns = new ArrayList<>();
        try (PreparedStatement select = connection.prepareStatement(SELECT_COLUMNS)) {
            select.setString(1, table);
            select.setArray(2, connection.createArrayOf("text", excluded));
            try (ResultSet rows = select.executeQuery()) {
                while (rows.next()) {
                    columns.add('"' + rows.getString(1) + '"');
                }
            }
        }
        return columns;
    }

    private static String qualified(String alias, List<String> columns) {
        return columns.stream().map(column -> alias + "." + column).collect(Collectors.joining(", "));
    }
}
