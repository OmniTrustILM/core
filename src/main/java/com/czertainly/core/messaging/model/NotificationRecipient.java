package com.czertainly.core.messaging.model;

import com.otilm.api.model.core.notification.RecipientType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@ToString
public class NotificationRecipient {
    private RecipientType recipientType;

    private UUID recipientUuid;

    public static List<NotificationRecipient> buildUserNotificationRecipient(UUID userUuid) {
        return userUuid != null ? List.of(new NotificationRecipient(RecipientType.USER, userUuid)) : null;
    }

    public static List<NotificationRecipient> buildGroupNotificationRecipient(UUID groupUuid) {
        return groupUuid != null ? List.of(new NotificationRecipient(RecipientType.GROUP, groupUuid)) : null;
    }

    public static List<NotificationRecipient> buildUsersAndGroupsNotificationRecipients(List<UUID> userUuids, List<UUID> groupUuids) {
        List<NotificationRecipient> recipients = new ArrayList<>();
        if(userUuids != null) {
            for(UUID userUuid : userUuids) {
                recipients.add(new NotificationRecipient(RecipientType.USER, userUuid));
            }
        }
        if(groupUuids != null) {
            for(UUID groupUuid : groupUuids) {
                recipients.add(new NotificationRecipient(RecipientType.GROUP, groupUuid));
            }
        }

        return recipients;
    }

    public static List<NotificationRecipient> buildRoleNotificationRecipient(UUID roleUuid) {
        return roleUuid != null ? List.of(new NotificationRecipient(RecipientType.ROLE, roleUuid)) : null;
    }
}
