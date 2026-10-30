package com.otilm.core.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.notification.NotificationSubject;

import java.util.List;

/**
 * A group or role with no members is ordinary configuration, not a failure, so the create methods report "nobody to
 * notify" by returning {@code null} rather than by throwing. Callers are expected to count what was actually created
 * and report an event that reached no one, rather than to treat every return as a delivery.
 */
public interface NotificationInternalService {

    /**
     * @return the created notification, never {@code null} -- the user is named explicitly.
     */
    NotificationDto createNotificationForUser(String message, String detail, String userUuid, Resource target,
            String targetUuids, NotificationSubject subject) throws ValidationException;

    NotificationDto createNotificationForGroup(String message, String detail, String groupUuid, Resource target,
            String targetUuids, NotificationSubject subject) throws ValidationException;

    NotificationDto createNotificationForRole(String message, String detail, String roleUuid, Resource target,
            String targetUuids, NotificationSubject subject) throws ValidationException;

    NotificationDto createNotificationForUser(String message, String detail, String userUuid, Resource target,
            String targetUuids) throws ValidationException;

    /**
     * @param subject which object inside the target the notification is about, or {@code null} when it is the target
     * itself
     * @return the created notification, or {@code null} when {@code userUuids} is null or empty.
     */
    NotificationDto createNotificationForUsers(String message, String detail, List<String> userUuids, Resource target,
            String targetUuids, NotificationSubject subject) throws ValidationException;

    NotificationDto createNotificationForUsers(String message, String detail, List<String> userUuids, Resource target,
            String targetUuids) throws ValidationException;

    /**
     * @return the created notification, or {@code null} when the group has no members.
     */
    NotificationDto createNotificationForGroup(String message, String detail, String groupUuid, Resource target,
            String targetUuids) throws ValidationException;

    /**
     * @return the created notification, or {@code null} when the role has no members.
     */
    NotificationDto createNotificationForRole(String message, String detail, String roleUuid, Resource target,
            String targetUuids) throws ValidationException;
}
