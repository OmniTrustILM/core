package db.migration;

import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.czertainly.core.util.DatabaseMigration;
import com.czertainly.core.util.MetaDefinitions;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@SuppressWarnings("java:S101")
public class V202509041555__CertificateRequestEntityBitmask extends BaseJavaMigration {

    public static final String KEY_USAGE = "key_usage";
    public static final String CERTIFICATE_REQUEST = "certificate_request";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202509041555__CertificateRequestEntityBitmask.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        migrateColumnToBitmask(context,
                raw -> MetaDefinitions.deserializeArrayString(raw).stream()
                .map(CertificateKeyUsage::fromCode)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(CertificateKeyUsage.class)))
               );
    }

    private <E extends Enum<E> & BitMaskEnum> void migrateColumnToBitmask(
            Context context,
            Function<String, EnumSet<E>> parser
    ) throws SQLException {

        Map<UUID, Integer> updates = new HashMap<>();

        try (Statement selectStatement = context.getConnection().createStatement()) {
            String selectSql = String.format("SELECT uuid, %s FROM %s", KEY_USAGE, CERTIFICATE_REQUEST);
            ResultSet rs = selectStatement.executeQuery(selectSql);

            while (rs.next()) {
                String rawValue = rs.getString(KEY_USAGE);
                int bitmask;
                if (rawValue == null || rawValue.isEmpty()) bitmask = 0;
                else {
                    EnumSet<E> values = parser.apply(rawValue);
                    bitmask = BitMaskEnum.convertSetToBitMask(values);
                }
                updates.put((UUID) rs.getObject("uuid"), bitmask);

            }

            selectStatement.execute(String.format("ALTER TABLE %s DROP COLUMN %s", CERTIFICATE_REQUEST, KEY_USAGE));
            selectStatement.execute(String.format("ALTER TABLE %s ADD COLUMN %s INTEGER", CERTIFICATE_REQUEST, KEY_USAGE));
        }

        String updateSql = String.format("UPDATE %s SET %s = ? WHERE uuid = ?", CERTIFICATE_REQUEST, KEY_USAGE);
        try (PreparedStatement ps = context.getConnection().prepareStatement(updateSql)) {
            for (Map.Entry<UUID, Integer> entry : updates.entrySet()) {
                ps.setInt(1, entry.getValue());                // bitmask
                ps.setObject(2, entry.getKey(), Types.OTHER);  // uuid
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }


}
