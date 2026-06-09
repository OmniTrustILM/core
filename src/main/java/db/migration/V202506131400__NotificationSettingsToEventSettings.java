package db.migration;

import com.otilm.core.util.DatabaseMigration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

@SuppressWarnings("java:S101")
public class V202506131400__NotificationSettingsToEventSettings extends BaseJavaMigration {

    private static final Map<String, String> NOTIFICATION_TYPE_TO_RESOURCE = Map.ofEntries(
            Map.entry("certificate_status_changed", "CERTIFICATE"),
            Map.entry("certificate_action_performed", "CERTIFICATE"),
            Map.entry("approval_requested", "APPROVAL"),
            Map.entry("approval_closed", "APPROVAL"),
            Map.entry("scheduled_job_completed", "SCHEDULED_JOB")
    );

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202506131400__NotificationSettingsToEventSettings.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        try (final Statement select = context.getConnection().createStatement()) {
            ResultSet notificationSettings = select.executeQuery("SELECT value FROM setting WHERE section = 'NOTIFICATIONS'");
            if (notificationSettings.next()) {
                String value = notificationSettings.getString("value");
                TypeReference<Map<String, String>> typeReference = new TypeReference<>() {
                };
                Map<String, String> typeToInstanceMap = new ObjectMapper().readValue(value, typeReference);
                Map<String, List<String>> instanceToTypes = typeToInstanceMap.entrySet()
                        .stream()
                        .collect(Collectors.groupingBy(
                                Map.Entry::getValue,
                                Collectors.mapping(Map.Entry::getKey, Collectors.toList())
                        ));

                String createNotificationProfile = """
                        INSERT INTO notification_profile (
                            uuid,
                            name,
                            created_at,
                            version_lock
                        ) VALUES (
                            ?,
                            ?,
                            NOW(),
                            0
                        );
                        """;

                String createNotificationProfileVersion = """
                        INSERT INTO notification_profile_version (
                            uuid,
                            notification_profile_uuid,
                            created_at,
                            version,
                            recipient_type,
                            notification_instance_ref_uuid,
                            internal_notification
                        ) VALUES (
                            ?,
                            ?,
                            NOW(),
                            1,
                            'DEFAULT',
                            ?,
                            TRUE
                        );
                        """;
                String createExecution = """
                        INSERT INTO execution (
                            uuid,
                            name,
                            type,
                            resource
                        ) VALUES (
                            ?,
                            ?,
                            'SEND_NOTIFICATION',
                            'ANY'
                        );
                        """;
                String createExecutionItem = """
                        INSERT INTO execution_item (
                            uuid,
                            execution_uuid,
                            notification_profile_uuid
                        ) VALUES (
                            ?,
                            ?,
                            ?
                        );
                        """;
                String createAction = """
                        INSERT INTO action (
                            uuid,
                            name,
                            resource
                        ) VALUES (
                            ?,
                            ?,
                            'ANY'
                        )
                        """;
                String createAction2Execution = """
                        INSERT INTO action_2_execution (
                            action_uuid,
                            execution_uuid
                        ) VALUES (
                            ?,
                            ?
                        )
                        """;

                String createTrigger = """
                        INSERT INTO trigger (
                            uuid,
                            name,
                            resource,
                            ignore_trigger
                        
                        ) VALUES (
                            ?,
                            ?,
                            ?,
                            FALSE
                        )
                        """;

                String createTrigger2Action = """
                        INSERT INTO trigger_2_action (
                            trigger_uuid,
                            action_uuid
                        ) VALUES (
                            ?,
                            ?
                        )
                        """;

                String createTriggerAssociation = """
                        INSERT INTO trigger_association (
                        uuid,
                        trigger_uuid,
                        trigger_order,
                        event,
                        override
                        ) VALUES (
                        ?,
                        ?,
                        0,
                        ?,
                        FALSE
                        )
                        """;
                try (PreparedStatement createNotificationProfilePs = context.getConnection().prepareStatement(createNotificationProfile);
                     PreparedStatement createNotificationProfileVersionPs = context.getConnection().prepareStatement(createNotificationProfileVersion);
                     PreparedStatement createExecutionPs = context.getConnection().prepareStatement(createExecution);
                     PreparedStatement createExecutionItemPs = context.getConnection().prepareStatement(createExecutionItem);
                     PreparedStatement createActionPs = context.getConnection().prepareStatement(createAction);
                     PreparedStatement createAction2ExecutionPs = context.getConnection().prepareStatement(createAction2Execution);
                     PreparedStatement createTriggerPs = context.getConnection().prepareStatement(createTrigger);
                     PreparedStatement createTrigger2ActionPs = context.getConnection().prepareStatement(createTrigger2Action);
                     PreparedStatement createTriggerAssociationPs = context.getConnection().prepareStatement(createTriggerAssociation)
                ) {
                    for (Map.Entry<String, List<String>> instanceToTypesEntry : instanceToTypes.entrySet()) {
                        try (final Statement selectNotificationInstance = context.getConnection().createStatement()) {
                            String notificationInstanceUuid = instanceToTypesEntry.getKey();
                            ResultSet notificationInstance = selectNotificationInstance.executeQuery("SELECT name FROM notification_instance_reference WHERE uuid = '%s'".formatted(notificationInstanceUuid));
                            if (notificationInstance.next()) {
                                String notificationInstanceName = notificationInstance.getString("name");
                                UUID notificationProfileUuid = UUID.randomUUID();
                                createNotificationProfilePs.setObject(1, notificationProfileUuid, Types.OTHER);
                                createNotificationProfilePs.setString(2, notificationInstanceName + "-profile-migrated");
                                createNotificationProfilePs.addBatch();

                                createNotificationProfileVersionPs.setObject(1, UUID.randomUUID(), Types.OTHER);
                                createNotificationProfileVersionPs.setObject(2, notificationProfileUuid, Types.OTHER);
                                createNotificationProfileVersionPs.setObject(3, UUID.fromString(notificationInstanceUuid), Types.OTHER);
                                createNotificationProfileVersionPs.addBatch();

                                UUID executionUuid = UUID.randomUUID();
                                createExecutionPs.setObject(1, executionUuid, Types.OTHER);
                                createExecutionPs.setString(2, notificationInstanceName + "-notify-execution-migrated");
                                createExecutionPs.addBatch();

                                createExecutionItemPs.setObject(1, UUID.randomUUID(), Types.OTHER);
                                createExecutionItemPs.setObject(2, executionUuid, Types.OTHER);
                                createExecutionItemPs.setObject(3, notificationProfileUuid, Types.OTHER);
                                createExecutionItemPs.addBatch();

                                UUID actionUuid = UUID.randomUUID();
                                createActionPs.setObject(1, actionUuid, Types.OTHER);
                                createActionPs.setString(2, notificationInstanceName + "-notify-action-migrated");
                                createActionPs.addBatch();

                                createAction2ExecutionPs.setObject(1, actionUuid, Types.OTHER);
                                createAction2ExecutionPs.setObject(2, executionUuid, Types.OTHER);
                                createAction2ExecutionPs.addBatch();


                                createTrigger2ActionPs.setObject(2, actionUuid, Types.OTHER);

                                createTriggerAndAssociations(instanceToTypesEntry.getValue(), createTriggerPs, createTrigger2ActionPs, createTriggerAssociationPs);
                            }

                        }
                    }
                    createNotificationProfilePs.executeBatch();
                    createNotificationProfileVersionPs.executeBatch();
                    createExecutionPs.executeBatch();
                    createExecutionItemPs.executeBatch();
                    createActionPs.executeBatch();
                    createAction2ExecutionPs.executeBatch();
                    createTriggerPs.executeBatch();
                    createTrigger2ActionPs.executeBatch();
                    createTriggerAssociationPs.executeBatch();
                }
                select.execute("DELETE FROM setting WHERE section = 'NOTIFICATIONS'");
            }
        }
    }

    private static void createTriggerAndAssociations(List<String> notificationTypes, PreparedStatement createTriggerPs, PreparedStatement createTrigger2ActionPs, PreparedStatement createTriggerAssociationPs) throws SQLException {
        for (String notificationType : notificationTypes) {
            String resource = NOTIFICATION_TYPE_TO_RESOURCE.get(notificationType);
            if (resource == null) continue;
            UUID triggerUuid = UUID.randomUUID();
            createTriggerPs.setObject(1, triggerUuid, Types.OTHER);
            createTriggerPs.setString(2, notificationType + "-trigger-migrated");
            createTriggerPs.setString(3, resource);
            createTriggerPs.addBatch();

            createTrigger2ActionPs.setObject(1, triggerUuid, Types.OTHER);
            createTrigger2ActionPs.addBatch();

            createTriggerAssociationPs.setObject(2, triggerUuid, Types.OTHER);

            createTriggerAssociationPs.setObject(1, UUID.randomUUID(), Types.OTHER);
            createTriggerAssociationPs.setString(3, notificationType.equals("scheduled_job_completed") ? "SCHEDULED_JOB_FINISHED" : notificationType.toUpperCase());
            createTriggerAssociationPs.addBatch();
        }
    }
}
