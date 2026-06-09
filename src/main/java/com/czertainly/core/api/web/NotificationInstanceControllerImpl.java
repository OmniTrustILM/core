package com.czertainly.core.api.web;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.web.NotificationInstanceController;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.notification.NotificationInstanceDto;
import com.czertainly.api.model.core.notification.NotificationInstanceRequestDto;
import com.czertainly.api.model.core.notification.NotificationInstanceUpdateRequestDto;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.NotificationInstanceExternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@RestController
public class NotificationInstanceControllerImpl implements NotificationInstanceController {

    private NotificationInstanceExternalService notificationInstanceService;

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_INSTANCE, operation = Operation.LIST)
    public List<NotificationInstanceDto> listNotificationInstances() {
        return notificationInstanceService.listNotificationInstances();
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_INSTANCE, operation = Operation.DETAIL)
    public NotificationInstanceDto getNotificationInstance(@LogResource(uuid = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        return notificationInstanceService.getNotificationInstance(UUID.fromString(uuid));
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_INSTANCE, operation = Operation.CREATE)
    public ResponseEntity<?> createNotificationInstance(
            @RequestBody NotificationInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        NotificationInstanceDto notificationInstance = notificationInstanceService.createNotificationInstance(request);

        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{uuid}")
                .buildAndExpand(notificationInstance.getUuid())
                .toUri();
        UuidDto dto = new UuidDto();
        dto.setUuid(notificationInstance.getUuid());
        return ResponseEntity.created(location).body(dto);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_INSTANCE, operation = Operation.UPDATE)
    public NotificationInstanceDto editNotificationInstance(
            @LogResource(uuid = true) @PathVariable String uuid,
            @RequestBody NotificationInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        return notificationInstanceService.editNotificationInstance(UUID.fromString(uuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.NOTIFICATION_INSTANCE, operation = Operation.DELETE)
    public void deleteNotificationInstance(@LogResource(uuid = true) @PathVariable String uuid) throws ConnectorException, NotFoundException {
        notificationInstanceService.deleteNotificationInstance(UUID.fromString(uuid));
    }

    @Override
    public List<DataAttribute> listMappingAttributes(String connectorUuid, String kind) throws ConnectorException, NotFoundException {
        return notificationInstanceService.listMappingAttributes(connectorUuid, kind);
    }

    @Autowired
    public void setNotificationInstanceService(NotificationInstanceExternalService notificationInstanceService) {
        this.notificationInstanceService = notificationInstanceService;
    }

}
