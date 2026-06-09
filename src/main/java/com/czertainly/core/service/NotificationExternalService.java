package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.notification.NotificationRequestDto;
import com.otilm.api.model.client.notification.NotificationResponseDto;

import java.util.List;

public interface NotificationExternalService {

    NotificationResponseDto listNotifications(NotificationRequestDto request);

    void deleteNotification(String uuid) throws NotFoundException;

    void markNotificationAsRead(String uuid) throws NotFoundException;

    void bulkDeleteNotifications(List<String> uuids);

    void bulkMarkNotificationAsRead(List<String> uuids);
}
