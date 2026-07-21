package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.notification.*;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.entity.workflows.Execution;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.workflows.ExecutionRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.util.RequestValidatorHelper;
import org.hibernate.exception.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class NotificationProfileServiceImpl implements NotificationProfileExternalService {

    private static final Logger logger = LoggerFactory.getLogger(NotificationProfileServiceImpl.class);

    private NotificationProfileServiceImpl self;
    private NotificationProfileRepository notificationProfileRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private ExecutionRepository executionRepository;
    private ResourceObjectAssociationService resourceObjectAssociationService;

    @Lazy
    @Autowired
    public void setSelf(NotificationProfileServiceImpl self) {
        this.self = self;
    }

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
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public NotificationProfileDetailDto editNotificationProfile(SecuredUUID uuid, NotificationProfileUpdateRequestDto updateRequestDto) throws NotFoundException {
        // Resolve recipient info from the request before opening the write transaction: recipient lookup
        // can call the auth service over HTTP and must not hold a DB connection or the profile row lock.
        List<NameAndUuidDto> recipients = resolveRecipients(updateRequestDto.getRecipientType(), updateRequestDto.getRecipientUuids());

        return self.persistEditedVersion(uuid, updateRequestDto, recipients);
    }

    @Transactional(rollbackFor = Exception.class)
    NotificationProfileDetailDto persistEditedVersion(SecuredUUID uuid, NotificationProfileUpdateRequestDto updateRequestDto, List<NameAndUuidDto> recipients) throws NotFoundException {
        // The row lock serializes concurrent edits; without it, both could read the same latest version and
        // insert duplicate version numbers.
        NotificationProfile notificationProfile = notificationProfileRepository.findAndLockByUuid(uuid.getValue()).orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        NotificationProfileVersion currentVersion = notificationProfileVersionRepository.findTopByNotificationProfileUuidOrderByVersionDesc(uuid.getValue()).orElseThrow(() -> new NotFoundException(NotificationProfileVersion.class, uuid));

        // Description lives on the profile, not on the version — persist it even when no new version is created
        if (!Objects.equals(notificationProfile.getDescription(), updateRequestDto.getDescription())) {
            notificationProfile.setDescription(updateRequestDto.getDescription());
            notificationProfileRepository.save(notificationProfile);
        }

        if (areVersionsEqual(currentVersion, updateRequestDto)) {
            logger.debug("Current version of notification profile {} is same as in request. New version is not created", notificationProfile.getName());
            return currentVersion.mapToDetailDto(recipients);
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
        try {
            notificationProfileVersion = notificationProfileVersionRepository.saveAndFlush(notificationProfileVersion);
        } catch (DataIntegrityViolationException e) {
            // Backstop for the unique (notification_profile_uuid, version) constraint, reachable only if a
            // writer bypasses the row lock above. Other integrity violations (e.g. a foreign key on a
            // concurrently deleted notification instance) are not concurrent-edit collisions and must surface as-is.
            if (isUniqueVersionViolation(e)) {
                throw new ValidationException("Notification profile %s was concurrently modified. Retry the edit.".formatted(notificationProfile.getName()));
            }
            throw e;
        }

        return notificationProfileVersion.mapToDetailDto(recipients);
    }

    private static boolean isUniqueVersionViolation(DataIntegrityViolationException e) {
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException constraintViolation) {
                return NotificationProfileVersion.UNIQUE_VERSION_CONSTRAINT.equalsIgnoreCase(constraintViolation.getConstraintName());
            }
        }
        return false;
    }

    private NotificationProfileDetailDto getNotificationProfileDetailDto(NotificationProfileVersion notificationProfileVersion) throws NotFoundException {
        return notificationProfileVersion.mapToDetailDto(resolveRecipients(notificationProfileVersion.getRecipientType(), notificationProfileVersion.getRecipientUuids()));
    }

    // retrieve recipients info and check for existence of such object
    private List<NameAndUuidDto> resolveRecipients(RecipientType recipientType, List<UUID> recipientUuids) throws NotFoundException {
        List<NameAndUuidDto> recipients = new ArrayList<>();
        if (recipientUuids != null) {
            for (UUID recipientUuid : recipientUuids) {
                recipients.add(resourceObjectAssociationService.getRecipientObjectInfo(recipientType, recipientUuid));
            }
        }

        return recipients;
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
