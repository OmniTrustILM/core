package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.core.notification.NotificationInstanceDto;
import com.czertainly.api.model.core.notification.NotificationInstanceRequestDto;
import com.czertainly.api.model.core.notification.NotificationInstanceUpdateRequestDto;

import java.util.List;
import java.util.UUID;

public interface NotificationInstanceExternalService {

    List<NotificationInstanceDto> listNotificationInstances();

    NotificationInstanceDto getNotificationInstance(UUID uuid) throws ConnectorException, NotFoundException;

    NotificationInstanceDto createNotificationInstance(NotificationInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    NotificationInstanceDto editNotificationInstance(UUID uuid, NotificationInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteNotificationInstance(UUID uuid) throws ConnectorException, NotFoundException;

    List<DataAttribute> listMappingAttributes(String connectorUuid, String kind) throws ConnectorException, NotFoundException;
}
