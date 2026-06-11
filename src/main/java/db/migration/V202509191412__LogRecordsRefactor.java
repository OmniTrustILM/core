package db.migration;

import com.otilm.core.util.DatabaseMigration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

@SuppressWarnings("java:S101")
public class V202509191412__LogRecordsRefactor extends BaseJavaMigration {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202509191412__LogRecordsRefactor.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        String updateLogRecord = """
                UPDATE audit_log SET log_record =
                log_record::jsonb || jsonb_build_object(
                  'timestamp', to_char(logged_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MSOF:TZM'),
                  'version', '1.1')
                #- '{resource, uuids}' #- '{resource, names}'
                #- '{affiliatedResource, uuids}' #- '{affiliatedResource, names}'
                """;
        String updateAuditLog = "UPDATE audit_log SET log_record = ?::jsonb WHERE id = ?";

        try (Statement statement = context.getConnection().createStatement();
             PreparedStatement updateStatement = context.getConnection().prepareStatement(updateAuditLog)
        ) {
            statement.execute("ALTER TABLE audit_log ADD COLUMN timestamp TIMESTAMP WITHOUT TIME ZONE");
            statement.execute("UPDATE audit_log SET timestamp = logged_at, version = '1.1'");
            statement.execute("ALTER TABLE audit_log ALTER COLUMN timestamp SET NOT NULL");
            statement.setFetchSize(100000);
            ResultSet auditLogs = statement.executeQuery("""
                    SELECT id,
                    log_record
                    FROM audit_log
                    WHERE log_record #> '{resource, names}' != 'null' OR log_record #> '{resource, uuids}' != 'null'
                       OR log_record #> '{affiliatedResource, names}' != 'null' OR log_record #> '{affiliatedResource, uuids}' != 'null';
                    """);
            while (auditLogs.next()) {
                String newJson = changeLogRecordToNewVersion(auditLogs.getString("log_record"));
                updateStatement.setString(1, newJson);
                updateStatement.setInt(2, auditLogs.getInt("id"));
                updateStatement.addBatch();
            }
            updateStatement.executeBatch();
            statement.execute(updateLogRecord);
        }
    }

    public static String changeLogRecordToNewVersion(String oldJson) throws IOException {
        JsonNode root = mapper.readTree(oldJson);
        // migrate "resource"
        updateResource(root, "resource");
        // migrate "affiliatedResource" if present
        updateResource(root, "affiliatedResource");
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    private static void updateResource(JsonNode root, String resource) {
        JsonNode resourceNode = root.get(resource);
        if (resourceNode != null && resourceNode.isObject()) {
            ObjectNode resourceObj = (ObjectNode) resourceNode;
            // collect names + uuids
            JsonNode names = resourceObj.get("names");
            JsonNode uuids = resourceObj.get("uuids");

            ArrayNode objects = mapper.createArrayNode();

            int maxSize = 0;
            maxSize = getMaxSize(names, maxSize);
            maxSize = getMaxSize(uuids, maxSize);

            for (int i = 0; i < maxSize; i++) {
                ObjectNode obj = mapper.createObjectNode();
                updateObjectProperty(names, i, obj, "name");
                updateObjectProperty(uuids, i, obj, "uuid");
                if (!obj.get("name").isNull() || !obj.get("uuid").isNull()) objects.add(obj);
            }
            resourceObj.set("objects", objects);
        }

    }

    private static void updateObjectProperty(JsonNode names, int i, ObjectNode obj, String name) {
        if (names != null && i < names.size() && !names.get(i).isNull()) {
            obj.put(name, names.get(i).asText());
        } else {
            obj.putNull(name);
        }
    }

    private static int getMaxSize(JsonNode names, int maxSize) {
        if (names != null && names.isArray()) {
            maxSize = Math.max(maxSize, names.size());
        }
        return maxSize;
    }

}
