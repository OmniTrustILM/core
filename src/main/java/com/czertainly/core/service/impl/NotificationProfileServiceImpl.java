package com.czertainly.core.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.notification.*;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.dao.entity.notifications.NotificationProfile;
import com.czertainly.core.dao.entity.notifications.NotificationProfileVersion;
import com.czertainly.core.dao.entity.workflows.Execution;
import com.czertainly.core.dao.repository.notifications.NotificationProfileRepository;
import com.czertainly.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.czertainly.core.dao.repository.workflows.ExecutionRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.NotificationProfileExternalService;
import com.czertainly.core.service.ResourceObjectAssociationService;
import com.czertainly.core.util.RequestValidatorHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class NotificationProfileServiceImpl implements NotificationProfileExternalService {

    private static final Logger logger = LoggerFactory.getLogger(NotificationProfileServiceImpl.class);

    private NotificationProfileRepository notificationProfileRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private ExecutionRepository executionRepository;
    private ResourceObjectAssociationService resourceObjectAssociationService;

    @Autowired
    public void setNotificationProfileRepository(NotificationProfileRepository notificationProfileRepository) {
        this.notificationProfileRepository = notificationProfileRepository;
    }

    @Autowired
    public void setNotificationProfileVersionRepository(NotificationProfileVersionRepository notificationProfileVersionRepository) {
        this.notificationProfileVersionRepository = notificationProfileVersionRepository;
    }

    @Autowired
    public void setExecutionRepository(ExecutionRepository executionRepository) {
        this.executionRepository = executionRepository;
    }

    @Autowired
    public void setResourceObjectAssociationService(ResourceObjectAssociationService resourceObjectAssociationService) {
        this.resourceObjectAssociationService = resourceObjectAssociationService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.LIST)
    public NotificationProfileResponseDto listNotificationProfiles(PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);

        SecurityFilter filter = SecurityFilter.create();
        final Pageable pageable = PageRequest.of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<NotificationProfile> notificationProfiles = notificationProfileRepository.findUsingSecurityFilter(filter, List.of(), null, pageable, null);
        final Long maxItems = notificationProfileRepository.countUsingSecurityFilter(filter, null);

        final NotificationProfileResponseDto responseDto = new NotificationProfileResponseDto();
        responseDto.setNotificationProfiles(notificationProfiles.stream().map(notificationProfile -> notificationProfile.getCurrentVersion().mapToDto()).toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));

        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.DETAIL)
    public NotificationProfileDetailDto getNotificationProfile(SecuredUUID uuid, Integer version) throws NotFoundException {
        NotificationProfileVersion notificationProfileVersion;
        if (version == null) {
            notificationProfileVersion = notificationProfileVersionRepository.findTopByNotificationProfileUuidOrderByVersionDesc(uuid.getValue()).orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        } else {
            notificationProfileVersion = notificationProfileVersionRepository.findByNotificationProfileUuidAndVersion(uuid.getValue(), version).orElseThrow(() -> new NotFoundException(NotificationProfileVersion.class, uuid));
        }

        return getNotificationProfileDetailDto(notificationProfileVersion);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.DELETE)
    public void deleteNotificationProfile(SecuredUUID uuid) throws NotFoundException {
        NotificationProfile notificationProfile = notificationProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));

        // check execution items referencing notification profile
        List<Execution> executions = executionRepository.findByItemsNotificationProfileUuid(uuid.getValue());
        if (!executions.isEmpty()) {
            throw new ValidationException("Cannot delete notification profile. %d execution(s) are referencing this notification profile: %s".formatted(executions.size(), executions.stream().map(Execution::getName).collect(Collectors.joining(", "))));
        }

        notificationProfileRepository.delete(notificationProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.CREATE)
    public NotificationProfileDetailDto createNotificationProfile(NotificationProfileRequestDto requestDto) throws AlreadyExistException, NotFoundException {
        if (notificationProfileRepository.findByName(requestDto.getName()).isPresent()) {
            throw new AlreadyExistException("Notification profile with name " + requestDto.getName() + " already exists.");
        }

        NotificationProfile notificationProfile = new NotificationProfile();
        notificationProfile.setName(requestDto.getName());
        notificationProfile.setDescription(requestDto.getDescription());
        notificationProfile = notificationProfileRepository.save(notificationProfile);

        NotificationProfileVersion notificationProfileVersion = new NotificationProfileVersion();
        notificationProfileVersion.setVersion(1);
        notificationProfileVersion.setNotificationProfileUuid(notificationProfile.getUuid());
        notificationProfileVersion.setNotificationProfile(notificationProfile);
        notificationProfileVersion.setRecipientType(requestDto.getRecipientType());
        notificationProfileVersion.setRecipientUuids(requestDto.getRecipientUuids());
        notificationProfileVersion.setNotificationInstanceRefUuid(requestDto.getNotificationInstanceUuid());
        notificationProfileVersion.setInternalNotification(requestDto.isInternalNotification());
        notificationProfileVersion.setFrequency(requestDto.getFrequency());
        notificationProfileVersion.setRepetitions(requestDto.getRepetitions());
        notificationProfile.getVersions().add(notificationProfileVersion);
        notificationProfileVersionRepository.save(notificationProfileVersion);

        return getNotificationProfileDetailDto(notificationProfileVersion);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.UPDATE)
    public NotificationProfileDetailDto editNotificationProfile(SecuredUUID uuid, NotificationProfileUpdateRequestDto updateRequestDto) throws NotFoundException {
        NotificationProfile notificationProfile = notificationProfileRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        NotificationProfileVersion currentVersion = notificationProfile.getCurrentVersion();

        if (areVersionsEqual(currentVersion, updateRequestDto)) {
            logger.debug("Current version of notification profile {} is same as in request. New version is not created", notificationProfile.getName());
            return getNotificationProfileDetailDto(currentVersion);
        }

        if (!Objects.equals(notificationProfile.getDescription(), updateRequestDto.getDescription())) {
            notificationProfile.setDescription(updateRequestDto.getDescription());
            notificationProfileRepository.save(notificationProfile);
        }

        NotificationProfileVersion notificationProfileVersion = new NotificationProfileVersion();
        notificationProfileVersion.setNotificationProfileUuid(notificationProfile.getUuid());
        notificationProfileVersion.setNotificationProfile(notificationProfile);
        notificationProfileVersion.setVersion(currentVersion.getVersion() + 1);
        notificationProfileVersion.setRecipientType(updateRequestDto.getRecipientType());
        notificationProfileVersion.setRecipientUuids(updateRequestDto.getRecipientUuids());
        notificationProfileVersion.setNotificationInstanceRefUuid(updateRequestDto.getNotificationInstanceUuid());
        notificationProfileVersion.setInternalNotification(updateRequestDto.isInternalNotification());
        notificationProfileVersion.setFrequency(updateRequestDto.getFrequency());
        notificationProfileVersion.setRepetitions(updateRequestDto.getRepetitions());
        notificationProfileVersion = notificationProfileVersionRepository.save(notificationProfileVersion);

        return getNotificationProfileDetailDto(notificationProfileVersion);
    }

    private NotificationProfileDetailDto getNotificationProfileDetailDto(NotificationProfileVersion notificationProfileVersion) throws NotFoundException {
        // retrieve recipients info and check for existence of such object
        List<NameAndUuidDto> recipients = new ArrayList<>();
        if (notificationProfileVersion.getRecipientUuids() != null) {
            recipients = new ArrayList<>();
            for (UUID recipientUuid : notificationProfileVersion.getRecipientUuids()) {
                recipients.add(resourceObjectAssociationService.getRecipientObjectInfo(notificationProfileVersion.getRecipientType(), recipientUuid));
            }
        }

        return notificationProfileVersion.mapToDetailDto(recipients);
    }

    private boolean areVersionsEqual(NotificationProfileVersion currentVersion, NotificationProfileUpdateRequestDto requestDto) {
        return currentVersion.getRecipientType() == requestDto.getRecipientType()
                && Objects.equals(currentVersion.getRecipientUuids(), requestDto.getRecipientUuids())
                && Objects.equals(currentVersion.getNotificationInstanceRefUuid(), requestDto.getNotificationInstanceUuid())
                && currentVersion.isInternalNotification() == requestDto.isInternalNotification()
                && Objects.equals(currentVersion.getFrequency(), requestDto.getFrequency())
                && Objects.equals(currentVersion.getRepetitions(), requestDto.getRepetitions());
    }
}
