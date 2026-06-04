package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.NotificationProfileController;
import com.czertainly.api.model.client.notification.NotificationProfileDetailDto;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.client.notification.NotificationProfileResponseDto;
import com.czertainly.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.NotificationProfileExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
public class NotificationProfileControllerImpl implements NotificationProfileController {

    private NotificationProfileExternalService notificationProfileService;

    @Autowired
    public void setNotificationProfileService(NotificationProfileExternalService notificationProfileService) {
        this.notificationProfileService = notificationProfileService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_PROFILE, operation = Operation.LIST)
    public NotificationProfileResponseDto listNotificationProfiles(PaginationRequestDto paginationRequestDto) {
        return notificationProfileService.listNotificationProfiles(paginationRequestDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_PROFILE, operation = Operation.DETAIL)
    public NotificationProfileDetailDto getNotificationProfile(String uuid, Integer version) throws NotFoundException {
        return notificationProfileService.getNotificationProfile(SecuredUUID.fromString(uuid), version);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_PROFILE, operation = Operation.DELETE)
    public void deleteNotificationProfile(String uuid) throws NotFoundException {
        notificationProfileService.deleteNotificationProfile(SecuredUUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<?> createNotificationProfile(NotificationProfileRequestDto notificationProfileRequestDto) throws NotFoundException, AlreadyExistException {
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService.createNotificationProfile(notificationProfileRequestDto);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(notificationProfileDetailDto.getUuid())
                .toUri();
        return ResponseEntity.created(location).body(notificationProfileDetailDto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_PROFILE, operation = Operation.UPDATE)
    public ResponseEntity<?> editNotificationProfile(String uuid, NotificationProfileUpdateRequestDto notificationProfileUpdateRequestDto) throws NotFoundException {
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService.editNotificationProfile(SecuredUUID.fromString(uuid), notificationProfileUpdateRequestDto);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(notificationProfileDetailDto.getUuid())
                .toUri();
        return ResponseEntity.status(HttpStatusCode.valueOf(200)).location(location).body(notificationProfileDetailDto);
    }
}
