package com.otilm.core.model.notification;

import com.otilm.api.model.core.auth.Resource;
import java.util.Date;
import java.util.UUID;

/**
 * One row of a user's notification listing: the notification joined with the recipient's own read mark. A query
 * projection rather than the DTO itself, so the subject reaches the client through the same mapping as a freshly
 * created notification.
 */
public record NotificationListItem(UUID uuid, String message, String detail, Date readAt, Date sentAt,
        Resource targetObjectType, String targetObjectIdentification, NotificationSubject subject) {
}
