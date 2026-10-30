package db.migration;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Array;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Backfills the normalized subject of registration placeholders so the registration-mode enrolment lookup
 * can prefilter by it in SQL. PENDING_REGISTRATION rows are included because they transition to REGISTERED
 * without their subject fields being rewritten; PENDING_APPROVAL rows are included because a rejected
 * approval restores the placeholder to REGISTERED, and non-placeholder rows in that state either already
 * carry a normalized subject or have it overwritten at issuance. A stored DN that does not re-parse stays
 * NULL: the identity match skips such rows, and a NULL normalized subject keeps the SQL prefilter equally
 * unable to return them.
 */
// Flyway requires the V<timestamp>__Name class name to resolve the migration version; it cannot match S101's
// class-name pattern.
@SuppressWarnings("java:S101")
public class V202608071000__RegistrationSubjectDnNormalizedMigration extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202608071000__RegistrationSubjectDnNormalizedMigration.class);

    private static final int BATCH_SIZE = 500;

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202608071000__RegistrationSubjectDnNormalizedMigration.getChecksum();
    }

    @Override
    public void migrate(Context context) throws SQLException {
        seedRdnOidRegistry(context);
        backfillNormalizedSubjects(context);
    }

    /**
     * Flyway runs before the Spring context populates the process-wide OID registry, so RDN codes would be
     * unresolvable and their DNs skipped as unparseable. Seed the RDN category with the same content the
     * runtime registry holds — custom rows merged with the SystemOid built-ins, custom row winning on an
     * OID collision — so the backfill parses stored DNs exactly as the runtime identity match does. The
     * merged map is published in a single call: publishing marks the category as loaded, which
     * PlatformX500NameStyle's construction requires even when no custom entries exist.
     */
    private void seedRdnOidRegistry(Context context) throws SQLException {
        Map<String, OidRecord> records = new HashMap<>();
        try (Statement select = context.getConnection().createStatement();
             ResultSet rows = select.executeQuery(
                     "SELECT oid, display_name, code, alt_codes FROM custom_oid_entry WHERE category = 'RDN_ATTRIBUTE_TYPE'")) {
            while (rows.next()) {
                Array altCodes = rows.getArray("alt_codes");
                records.put(rows.getString("oid"), OidRecord.builder()
                        .displayName(rows.getString("display_name"))
                        .code(rows.getString("code"))
                        .altCodes(altCodes == null ? List.of() : Arrays.stream((String[]) altCodes.getArray())
                                .filter(Objects::nonNull)
                                .toList())
                        .build());
            }
        }
        Arrays.stream(SystemOid.values())
                .filter(oid -> oid.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE)
                .forEach(oid -> records.putIfAbsent(oid.getOid(), OidRecord.builder()
                        .displayName(oid.getDisplayName())
                        .code(oid.getCode())
                        .altCodes(oid.getAltCodes())
                        .system(true)
                        .build()));
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, records);
    }

    private void backfillNormalizedSubjects(Context context) throws SQLException {
        int backfilled = 0;
        int skipped = 0;
        int pending = 0;
        try (Statement select = context.getConnection().createStatement();
             PreparedStatement update = context.getConnection().prepareStatement(
                     "UPDATE certificate SET subject_dn_normalized = ? WHERE uuid = ?")) {
            // Stream the source rows instead of materializing the whole inventory: the migration runs inside
            // Flyway's transaction (autoCommit off), so a fetch size opens a server-side cursor, and the batch
            // is flushed every BATCH_SIZE rows so neither the result set nor the pending updates grow with the
            // registration count.
            select.setFetchSize(BATCH_SIZE);
            try (ResultSet rows = select.executeQuery(
                    "SELECT uuid, subject_dn FROM certificate "
                            + "WHERE state IN ('REGISTERED', 'PENDING_REGISTRATION', 'PENDING_APPROVAL') "
                            + "AND subject_dn_normalized IS NULL")) {
                while (rows.next()) {
                    String certificateUuid = rows.getString("uuid");
                    String normalized;
                    try {
                        normalized = CertificateUtil.normalizeStoredSubjectDn(rows.getString("subject_dn"));
                    } catch (RuntimeException e) {
                        logger.warn("Skipping normalized subject backfill of certificate {}: the stored subject DN"
                                + " does not re-parse, so registration-mode enrolment cannot match this row. Cause: {}",
                                certificateUuid, e.getMessage());
                        skipped++;
                        continue;
                    }
                    update.setString(1, normalized);
                    update.setObject(2, UUID.fromString(certificateUuid));
                    update.addBatch();
                    backfilled++;
                    if (++pending == BATCH_SIZE) {
                        update.executeBatch();
                        update.clearBatch();
                        pending = 0;
                    }
                }
                if (pending > 0) {
                    update.executeBatch();
                }
            }
        }
        logger.info("Normalized subject backfill finished: {} rows backfilled, {} rows skipped.", backfilled, skipped);
    }
}
