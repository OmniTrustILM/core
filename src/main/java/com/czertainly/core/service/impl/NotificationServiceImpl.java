package com.czertainly.core.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.notification.NotificationDto;
import com.czertainly.api.model.client.notification.NotificationRequestDto;
import com.czertainly.api.model.client.notification.NotificationResponseDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.core.dao.entity.notifications.Notification;
import com.czertainly.core.dao.entity.notifications.NotificationRecipient;
import com.czertainly.core.dao.repository.notifications.NotificationRecipientRepository;
import com.czertainly.core.dao.repository.notifications.NotificationRepository;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.ExternalAuthorizationMissing;
import com.czertainly.core.service.NotificationExternalService;
import com.czertainly.core.service.NotificationInternalService;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.RequestValidatorHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class NotificationServiceImpl implements NotificationExternalService, NotificationInternalService {

    private static final Logger logger = LoggerFactory.getLogger(NotificationServiceImpl.class);

    private NotificationRepository notificationRepository;
    private NotificationRecipientRepository notificationRecipientRepository;
    private UserManagementApiClient userManagementApiClient;
    private RoleManagementApiClient roleManagementApiClient;

    @Autowired
    public void setNotificationRepository(NotificationRepository notificationRepository) {
        this.notificationRepository = notificationRepository;
    }

    @Autowired
    public void setNotificationRecipientRepository(NotificationRecipientRepository notificationRecipientRepository) {
        this.notificationRecipientRepository = notificationRecipientRepository;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @Override
    public NotificationDto createNotificationForUser(String message, String detail, String userUuid, Resource target, String targetUuids) throws ValidationException {
        return createNotificationForUsers(message, detail, List.of(userUuid), target, targetUuids);
    }

    @Override
    public NotificationDto createNotificationForUsers(String message, String detail, List<String> userUuids, Resource target, String targetUuids) throws ValidationException {
        Notification notification = new Notification();
        notification.setUuid(UUID.randomUUID());
        notification.setMessage(message);
        notification.setDetail(detail);
        notification.setTargetObjectType(target);
        notification.setTargetObjectIdentification(targetUuids);

        Set<NotificationRecipient> notificationRecipients = new HashSet<>();
        for (String userUuid : userUuids) {
            NotificationRecipient notificationRecipient = new NotificationRecipient();
            notificationRecipient.setUserUuid(UUID.fromString(userUuid));
            notificationRecipient.setNotificationUuid(notification.getUuid());
            notificationRecipients.add(notificationRecipient);
        }
        notification.setNotificationRecipients(notificationRecipients);

        if (notificationRecipients.isEmpty()) {
            throw new ValidationException("Unable to create notification for no recipients.");
        }

        notificationRepository.save(notification);
        return notification.mapToDto();
    }

    @Override
    public NotificationDto createNotificationForGroup(String message, String detail, String groupUuid, Resource target, String targetUuids) throws ValidationException {
        return createNotificationForUsers(message, detail, userManagementApiClient.getUsers().getData().stream().filter(u -> u.getGroups().stream().anyMatch(g -> g.getUuid().equals(groupUuid))).map(UserDto::getUuid).toList(), target, targetUuids);
    }

    @Override
    public NotificationDto createNotificationForRole(String message, String detail, String roleUuid, Resource target, String targetUuids) throws ValidationException {
        return createNotificationForUsers(message, detail, roleManagementApiClient.getRoleUsers(roleUuid).stream().map(UserDto::getUuid).toList(), target, targetUuids);
    }

    @Override
    @ExternalAuthorizationMissing
    public NotificationResponseDto listNotifications(NotificationRequestDto request) {
        RequestValidatorHelper.revalidatePaginationRequestDto(request);
        final Pageable pageable = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());
        final UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserProfile().getUser().getUuid());

        final Page<NotificationDto> pagedNotifications = request.isUnread()
                ? notificationRecipientRepository.findUnreadByUserUuid(loggedUserUuid, pageable)
                : notificationRecipientRepository.findByUserUuid(loggedUserUuid, pageable);

        final NotificationResponseDto responseDto = new NotificationResponseDto();
        responseDto.setItems(pagedNotifications.getContent());
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(pagedNotifications.getTotalElements());
        responseDto.setTotalPages(pagedNotifications.getTotalPages());

        return responseDto;
    }

    @Override
    @ExternalAuthorizationMissing
    public void deleteNotification(String uuid) throws NotFoundException {
        final UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserProfile().getUser().getUuid());
        Notification notification = notificationRepository.findByUuid(SecuredUUID.fromString(uuid)).orElseThrow(() -> new NotFoundException(Notification.class, uuid));
        notification.getNotificationRecipients().removeIf(r -> r.getUserUuid().equals(loggedUserUuid));
        if (notification.getNotificationRecipients().isEmpty()) {
            notificationRepository.delete(notification);
        } else {
            notificationRepository.save(notification);
        }
    }

    @Override
    @ExternalAuthorizationMissing
    public void markNotificationAsRead(String uuid) throws NotFoundException {
        final UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserProfile().getUser().getUuid());
        Notification notification = notificationRepository.findByUuid(SecuredUUID.fromString(uuid)).orElseThrow(() -> new NotFoundException(Notification.class, uuid));
        for (NotificationRecipient recipient : notification.getNotificationRecipients()) {
            if (recipient.getUserUuid().equals(loggedUserUuid)) {
                if (recipient.getReadAt() == null) {
                    recipient.setReadAt(new Date());
                    notificationRepository.save(notification);
                }
                break;
            }
        }
    }

    @Override
    @ExternalAuthorizationMissing
    public void bulkDeleteNotifications(List<String> uuids) {
        for (String uuid : uuids) {
            try {
                deleteNotification(uuid);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }

    @Override
    @ExternalAuthorizationMissing
    public void bulkMarkNotificationAsRead(List<String> uuids) {
        for (String uuid : uuids) {
            try {
                markNotificationAsRead(uuid);
            } catch (NotFoundException e) {
                logger.warn(e.getMessage());
            }
        }
    }
}
