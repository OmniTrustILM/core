package com.otilm.core.mapper.notifications;

import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.core.model.notification.NotificationListItem;
import com.otilm.core.model.notification.NotificationSubject;

public final class NotificationMapper {

    private NotificationMapper() {
    }

    public static NotificationDto toDto(NotificationListItem item) {
        NotificationDto dto = new NotificationDto(item.uuid(), item.message(), item.detail(), item.readAt(),
                item.sentAt(), item.targetObjectType(), item.targetObjectIdentification());
        applySubject(dto, item.subject());
        return dto;
    }

    public static void applySubject(NotificationDto dto, NotificationSubject subject) {
        if (subject == null) {
            return;
        }
        dto.setSubjectObjectType(subject.type());
        dto.setSubjectObjectIdentification(subject.identification());
        dto.setSubjectParentIdentification(subject.parentIdentification());
    }
}
