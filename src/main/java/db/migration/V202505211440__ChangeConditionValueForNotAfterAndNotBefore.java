package db.migration;

import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.UUID;

@SuppressWarnings("java:S101")
public class V202505211440__ChangeConditionValueForNotAfterAndNotBefore extends BaseJavaMigration {

    public static final String S_T_23_59_59_Z = "\"%sT23:59:59.999Z\"";
    public static final String S_T_00_00_00_Z = "\"%sT00:00:00Z\"";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202505211440__ChangeConditionValueForNotAfterAndNotBefore.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        try (final Statement select = context.getConnection().createStatement()) {
            ResultSet conditions = select.executeQuery("SELECT uuid, value, operator, condition_uuid, field_identifier FROM condition_item WHERE field_identifier IN ('NOT_AFTER','NOT_BEFORE') AND operator IN ('EQUALS', 'NOT_EQUALS','GREATER', 'LESSER', 'GREATER_OR_EQUAL', 'LESSER_OR_EQUAL');");
            String updateValue = "UPDATE condition_item SET value = (?::jsonb) WHERE uuid = ?";
            String addConditionItem = """
                    INSERT INTO condition_item (
                        uuid,
                        condition_uuid,
                        field_source,
                        field_identifier,
                        operator,
                        value
                    ) VALUES (
                        ?,
                        ?,
                        'PROPERTY',
                        ?,
                        ?,
                        (?::jsonb)
                    );
                    """;
            String removeCondition = "DELETE FROM condition_item WHERE uuid = ?";
            try (PreparedStatement preparedStatement = context.getConnection().prepareStatement(updateValue);
                 PreparedStatement preparedStatementAddCi = context.getConnection().prepareStatement(addConditionItem);
                 PreparedStatement psDeleteConditionItem = context.getConnection().prepareStatement(removeCondition)) {

                while (conditions.next()) {
                    String operator = conditions.getString("operator");
                    String value = conditions.getObject("value").toString().replace("\"", "");
                    String uuid = conditions.getString("uuid");
                    switch (operator) {
                        case "GREATER" -> {
                            // Greater than dd.mm.yyyy = Greater than dd.mm.yyyyT23:59:59
                            preparedStatement.setObject(1, S_T_23_59_59_Z.formatted(value));
                            preparedStatement.setObject(2, uuid, Types.OTHER);
                            preparedStatement.addBatch();

                        }
                        case "GREATER_OR_EQUAL" -> {
                            // Greater than or equal to dd.mm.yyyy = Greater than or equal to dd.mm.yyyyT00:00:00
                            preparedStatement.setObject(1, S_T_00_00_00_Z.formatted(value));
                            preparedStatement.setObject(2, uuid, Types.OTHER);
                            preparedStatement.addBatch();

                        }
                        case "LESSER" -> {
                            // Lesser than dd.mm.yyyy = Lesser than dd.mm.yyyyT00:00:00
                            preparedStatement.setObject(1, S_T_00_00_00_Z.formatted(value));
                            preparedStatement.setObject(2, uuid, Types.OTHER);
                            preparedStatement.addBatch();

                        }
                        case "LESSER_OR_EQUAL" -> {
                            // Lesser than or equal to dd.mm.yyyy = Lesser than or equal to dd.mm.yyyyT23:59:59
                            preparedStatement.setObject(1, S_T_23_59_59_Z.formatted(value));
                            preparedStatement.setObject(2, uuid, Types.OTHER);
                            preparedStatement.addBatch();

                        }
                        case "EQUALS" -> {
                            // Equal to dd.mm.yyyy = Lesser than or equal to dd.mm.yyyyT23:59:59 and Greater than or equal to dd.mm.yyyyT00:00:00
                            preparedStatementAddCi.setObject(1, UUID.randomUUID(), Types.OTHER);
                            preparedStatementAddCi.setObject(2, conditions.getString("condition_uuid"), Types.OTHER);
                            preparedStatementAddCi.setString(3, conditions.getString("field_identifier"));
                            preparedStatementAddCi.setString(4, "LESSER_OR_EQUAL");
                            preparedStatementAddCi.setObject(5, S_T_23_59_59_Z.formatted(value));

                            preparedStatementAddCi.addBatch();

                            preparedStatementAddCi.setObject(1, UUID.randomUUID(), Types.OTHER);
                            preparedStatementAddCi.setString(4, "GREATER_OR_EQUAL");
                            preparedStatementAddCi.setString(5, S_T_00_00_00_Z.formatted(value));
                            preparedStatementAddCi.addBatch();

                            psDeleteConditionItem.setObject(1, uuid, Types.OTHER);
                            psDeleteConditionItem.addBatch();
                        }
                        case "NOT_EQUALS" -> {
                            // Not Equal to dd.mm.yyyy = Lesser than dd.mm.yyyyT00:00:00 and Greater than dd.mm.yyyyT23:59:59
                            preparedStatementAddCi.setObject(1, UUID.randomUUID(), Types.OTHER);
                            preparedStatementAddCi.setObject(2, conditions.getString("condition_uuid"), Types.OTHER);
                            preparedStatementAddCi.setString(3, conditions.getString("field_identifier"));
                            preparedStatementAddCi.setString(4, "LESSER");
                            preparedStatementAddCi.setString(5, S_T_00_00_00_Z.formatted(value));

                            preparedStatementAddCi.addBatch();

                            preparedStatementAddCi.setObject(1, UUID.randomUUID(), Types.OTHER);
                            preparedStatementAddCi.setString(4, "GREATER");
                            preparedStatementAddCi.setString(5, S_T_23_59_59_Z.formatted(value));
                            preparedStatementAddCi.addBatch();

                            psDeleteConditionItem.setObject(1, uuid, Types.OTHER);
                            psDeleteConditionItem.addBatch();
                        }
                        default -> {
                            // Will not be reached because of SELECT
                        }
                    }
                }
                preparedStatement.executeBatch();
                preparedStatementAddCi.executeBatch();
                psDeleteConditionItem.executeBatch();
            }
        }
    }
}
