package com.czertainly.core.service;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.notification.NotificationDto;
import com.czertainly.api.model.core.auth.Resource;

import java.util.List;

public interface NotificationInternalService {

    NotificationDto createNotificationForUser(String message, String detail, String userUuid, Resource target, String targetUuids) throws ValidationException;

    NotificationDto createNotificationForUsers(String message, String detail, List<String> userUuids, Resource target, String targetUuids) throws ValidationException;

    NotificationDto createNotificationForGroup(String message, String detail, String groupUuid, Resource target, String targetUuids) throws ValidationException;

    NotificationDto createNotificationForRole(String message, String detail, String roleUuid, Resource target, String targetUuids) throws ValidationException;
}
