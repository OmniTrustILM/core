package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.notification.NotificationProfileDetailDto;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.client.notification.NotificationProfileResponseDto;
import com.czertainly.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.security.authz.SecuredUUID;

public interface NotificationProfileExternalService {

    NotificationProfileResponseDto listNotificationProfiles(PaginationRequestDto paginationRequestDto);

    NotificationProfileDetailDto getNotificationProfile(SecuredUUID uuid, Integer version) throws NotFoundException;

    void deleteNotificationProfile(SecuredUUID uuid) throws NotFoundException;

    NotificationProfileDetailDto createNotificationProfile(NotificationProfileRequestDto requestDto) throws AlreadyExistException, NotFoundException;

    NotificationProfileDetailDto editNotificationProfile(SecuredUUID uuid, NotificationProfileUpdateRequestDto updateRequestDto) throws NotFoundException;
}
