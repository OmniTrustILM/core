package com.czertainly.core.api.web;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.NotificationController;
import com.czertainly.api.model.client.notification.NotificationRequestDto;
import com.czertainly.api.model.client.notification.NotificationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.NotificationExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class NotificationControllerImpl implements NotificationController {

    private NotificationExternalService notificationService;

    @Autowired
    public void setNotificationService(NotificationExternalService notificationService) {
        this.notificationService = notificationService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION, operation = Operation.LIST)
    public NotificationResponseDto listNotifications(NotificationRequestDto request) {
        return notificationService.listNotifications(request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION, operation = Operation.DELETE)
    public void deleteNotification(@LogResource(uuid = true) String uuid) throws NotFoundException {
        notificationService.deleteNotification(uuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION, operation = Operation.MARK_AS_READ)
    public void markNotificationAsRead(@LogResource(uuid = true) String uuid) throws NotFoundException {
        notificationService.markNotificationAsRead(uuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION, operation = Operation.DELETE)
    public void bulkDeleteNotification(List<String> uuids) {
        notificationService.bulkDeleteNotifications(uuids);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION, operation = Operation.MARK_AS_READ)
    public void bulkMarkNotificationAsRead(List<String> uuids) {
        notificationService.bulkMarkNotificationAsRead(uuids);
    }
}
