package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.core.notification.NotificationInstanceDto;
import com.otilm.api.model.core.notification.NotificationInstanceRequestDto;
import com.otilm.api.model.core.notification.NotificationInstanceUpdateRequestDto;

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
