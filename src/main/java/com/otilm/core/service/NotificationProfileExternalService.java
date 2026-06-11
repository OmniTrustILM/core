package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.client.notification.NotificationProfileResponseDto;
import com.otilm.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.security.authz.SecuredUUID;

public interface NotificationProfileExternalService {

    NotificationProfileResponseDto listNotificationProfiles(PaginationRequestDto paginationRequestDto);

    NotificationProfileDetailDto getNotificationProfile(SecuredUUID uuid, Integer version) throws NotFoundException;

    void deleteNotificationProfile(SecuredUUID uuid) throws NotFoundException;

    NotificationProfileDetailDto createNotificationProfile(NotificationProfileRequestDto requestDto) throws AlreadyExistException, NotFoundException;

    NotificationProfileDetailDto editNotificationProfile(SecuredUUID uuid, NotificationProfileUpdateRequestDto updateRequestDto) throws NotFoundException;
}
