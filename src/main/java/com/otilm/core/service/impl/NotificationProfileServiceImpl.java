package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.client.notification.NotificationProfileResponseDto;
import com.otilm.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.entity.notifications.NotificationProfile_;
import com.otilm.core.dao.entity.workflows.Execution;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.workflows.ExecutionRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.service.NotificationProfileInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.notifications.NotificationDataCategoryGate;
import com.otilm.core.util.RequestValidatorHelper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.hibernate.exception.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service(Resource.Codes.NOTIFICATION_PROFILE)
@Transactional(rollbackFor = Exception.class)
public class NotificationProfileServiceImpl
        implements
            NotificationProfileExternalService,
            NotificationProfileInternalService {

    private static final Logger logger = LoggerFactory.getLogger(NotificationProfileServiceImpl.class);

    private EntityManager entityManager;

    private NotificationProfileServiceImpl self;
    private NotificationProfileRepository notificationProfileRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;

    private ExecutionRepository executionRepository;
    private ResourceObjectAssociationService resourceObjectAssociationService;
    private NotificationDataCategoryGate notificationDataCategoryGate;

    private CommentInternalService commentService;

    @Autowired
    public void setCommentService(CommentInternalService commentService) {
        this.commentService = commentService;
    }

    @Lazy
    @Autowired
    public void setSelf(NotificationProfileServiceImpl self) {
        this.self = self;
    }

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Autowired
    public void setNotificationProfileRepository(NotificationProfileRepository notificationProfileRepository) {
        this.notificationProfileRepository = notificationProfileRepository;
    }

    @Autowired
    public void setNotificationProfileVersionRepository(
            NotificationProfileVersionRepository notificationProfileVersionRepository) {
        this.notificationProfileVersionRepository = notificationProfileVersionRepository;
    }

    @Autowired
    public void setNotificationInstanceReferenceRepository(
            NotificationInstanceReferenceRepository notificationInstanceReferenceRepository) {
        this.notificationInstanceReferenceRepository = notificationInstanceReferenceRepository;
    }

    @Autowired
    public void setExecutionRepository(ExecutionRepository executionRepository) {
        this.executionRepository = executionRepository;
    }

    @Autowired
    public void setResourceObjectAssociationService(ResourceObjectAssociationService resourceObjectAssociationService) {
        this.resourceObjectAssociationService = resourceObjectAssociationService;
    }

    @Autowired
    public void setNotificationDataCategoryGate(NotificationDataCategoryGate notificationDataCategoryGate) {
        this.notificationDataCategoryGate = notificationDataCategoryGate;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.LIST)
    public NotificationProfileResponseDto listNotificationProfiles(PaginationRequestDto paginationRequestDto) {
        RequestValidatorHelper.revalidatePaginationRequestDto(paginationRequestDto);

        SecurityFilter filter = SecurityFilter.create();
        final Pageable pageable = PageRequest
                .of(paginationRequestDto.getPageNumber() - 1, paginationRequestDto.getItemsPerPage());
        final List<NotificationProfile> notificationProfiles = notificationProfileRepository
                .findUsingSecurityFilter(filter, List.of(), null, pageable, null);
        final Long maxItems = notificationProfileRepository.countUsingSecurityFilter(filter, null);

        final NotificationProfileResponseDto responseDto = new NotificationProfileResponseDto();
        responseDto
                .setNotificationProfiles(notificationProfiles
                        .stream()
                        .map(notificationProfile -> notificationProfile.getCurrentVersion().mapToDto())
                        .toList());
        responseDto.setItemsPerPage(paginationRequestDto.getItemsPerPage());
        responseDto.setPageNumber(paginationRequestDto.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / paginationRequestDto.getItemsPerPage()));

        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.DETAIL)
    public NotificationProfileDetailDto getNotificationProfile(SecuredUUID uuid, Integer version)
            throws NotFoundException {
        NotificationProfileVersion notificationProfileVersion;
        if (version == null) {
            notificationProfileVersion = notificationProfileVersionRepository
                    .findTopByNotificationProfileUuidOrderByVersionDesc(uuid.getValue())
                    .orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        } else {
            notificationProfileVersion = notificationProfileVersionRepository
                    .findByNotificationProfileUuidAndVersion(uuid.getValue(), version)
                    .orElseThrow(() -> new NotFoundException(NotificationProfileVersion.class, uuid));
        }

        return getNotificationProfileDetailDto(notificationProfileVersion);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.DELETE)
    public void deleteNotificationProfile(SecuredUUID uuid) throws NotFoundException {
        NotificationProfile notificationProfile = notificationProfileRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));

        // check execution items referencing notification profile
        List<Execution> executions = executionRepository.findByItemsNotificationProfileUuid(uuid.getValue());
        if (!executions.isEmpty()) {
            throw new ValidationException(
                    "Cannot delete notification profile. %d execution(s) are referencing this notification profile: %s"
                            .formatted(executions.size(),
                                    executions.stream().map(Execution::getName).collect(Collectors.joining(", "))));
        }

        commentService.removeObjectComments(Resource.NOTIFICATION_PROFILE, notificationProfile.getUuid());
        notificationProfileRepository.delete(notificationProfile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.CREATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
    public NotificationProfileDetailDto createNotificationProfile(NotificationProfileRequestDto requestDto)
            throws AlreadyExistException, NotFoundException {
        validateNotificationInstanceExists(requestDto.getNotificationInstanceUuid());
        // The gate calls the authorization service over HTTP and must not hold a DB connection,
        // so it runs here while the writes happen in the self-proxied transactional method below.
        if (requestDto.getEventDataCategories() != null) {
            requestDto.setEventDataCategories(normalizeEventDataCategories(requestDto.getEventDataCategories()));
        }
        Set<NotificationDataCategory> gatedCategories = gatedCategoriesRequiringAuthorization(List.of(), null,
                requestDto.getEventDataCategories(), requestDto.getNotificationInstanceUuid());
        if (!gatedCategories.isEmpty()) {
            notificationDataCategoryGate.assertCanEnable(gatedCategories);
        }

        return self.persistNewProfile(requestDto);
    }

    @Transactional(rollbackFor = Exception.class)
    NotificationProfileDetailDto persistNewProfile(NotificationProfileRequestDto requestDto)
            throws AlreadyExistException, NotFoundException {
        if (notificationProfileRepository.findByName(requestDto.getName()).isPresent()) {
            throw new AlreadyExistException(
                    "Notification profile with name " + requestDto.getName() + " already exists.");
        }

        NotificationProfile notificationProfile = new NotificationProfile();
        notificationProfile.setName(requestDto.getName());
        notificationProfile.setDescription(requestDto.getDescription());
        if (requestDto.getEventDataCategories() != null) {
            notificationProfile.setEventDataCategories(requestDto.getEventDataCategories());
        }
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
    @Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
    public NotificationProfileDetailDto editNotificationProfile(SecuredUUID uuid,
            NotificationProfileUpdateRequestDto updateRequestDto) throws NotFoundException {
        validateNotificationInstanceExists(updateRequestDto.getNotificationInstanceUuid());
        // Resolve recipient info from the request before opening the write transaction: recipient lookup
        // can call the auth service over HTTP and must not hold a DB connection or the profile row lock.
        List<NameAndUuidDto> recipients = resolveRecipients(updateRequestDto.getRecipientType(),
                updateRequestDto.getRecipientUuids());

        // The category gate also calls the authorization service over HTTP, so it is evaluated here
        // against an unlocked read while persistEditedVersion re-asserts the decision under the row lock.
        if (updateRequestDto.getEventDataCategories() != null) {
            updateRequestDto
                    .setEventDataCategories(normalizeEventDataCategories(updateRequestDto.getEventDataCategories()));
        }
        NotificationProfile currentProfile = notificationProfileRepository
                .findById(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        NotificationProfileVersion currentVersion = notificationProfileVersionRepository
                .findTopByNotificationProfileUuidOrderByVersionDesc(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(NotificationProfileVersion.class, uuid));
        Set<NotificationDataCategory> authorizedGatedCategories = gatedCategoriesRequiringAuthorization(
                currentProfile.getEventDataCategories(), currentVersion.getNotificationInstanceRefUuid(),
                updateRequestDto.getEventDataCategories(), updateRequestDto.getNotificationInstanceUuid());
        if (!authorizedGatedCategories.isEmpty()) {
            notificationDataCategoryGate.assertCanEnable(authorizedGatedCategories);
        }

        // The transaction boundary comes from the self-proxied call; invoking persistEditedVersion directly
        // on `this` would skip the @Transactional advice and reintroduce the version race.
        return self.persistEditedVersion(uuid, updateRequestDto, recipients, authorizedGatedCategories);
    }

    @Transactional(rollbackFor = Exception.class)
    NotificationProfileDetailDto persistEditedVersion(SecuredUUID uuid,
            NotificationProfileUpdateRequestDto updateRequestDto, List<NameAndUuidDto> recipients,
            Set<NotificationDataCategory> authorizedGatedCategories) throws NotFoundException {
        // The row lock serializes concurrent edits; without it, both could read the same latest version and
        // insert duplicate version numbers.
        NotificationProfile notificationProfile = notificationProfileRepository
                .findAndLockByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(NotificationProfile.class, uuid));
        // Under open-session-in-view the orchestrator's unlocked read is already in this persistence
        // context, so the locking finder can return that stale managed instance; refresh re-reads the
        // now-locked row so every check below sees post-lock state.
        entityManager.refresh(notificationProfile);
        NotificationProfileVersion currentVersion = notificationProfileVersionRepository
                .findTopByNotificationProfileUuidOrderByVersionDesc(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(NotificationProfileVersion.class, uuid));
        entityManager.refresh(currentVersion);

        // The gate ran outside this transaction against an unlocked read. If a concurrent edit changed
        // the gate-relevant state in between, the pre-lock authorization no longer covers this request:
        // fail closed with a retry rather than calling the authorization service under the row lock.
        Set<NotificationDataCategory> gatedCategoriesUnderLock = gatedCategoriesRequiringAuthorization(
                notificationProfile.getEventDataCategories(), currentVersion.getNotificationInstanceRefUuid(),
                updateRequestDto.getEventDataCategories(), updateRequestDto.getNotificationInstanceUuid());
        if (!authorizedGatedCategories.containsAll(gatedCategoriesUnderLock)) {
            throw new ValidationException("Notification profile %s was concurrently modified. Retry the edit."
                    .formatted(notificationProfile.getName()));
        }

        applyEventDataCategories(notificationProfile, updateRequestDto);

        // Description lives on the profile, not on the version — persist it even when no new version is created
        if (!Objects.equals(notificationProfile.getDescription(), updateRequestDto.getDescription())) {
            notificationProfile.setDescription(updateRequestDto.getDescription());
            notificationProfileRepository.save(notificationProfile);
        }

        if (areVersionsEqual(currentVersion, updateRequestDto)) {
            logger
                    .debug("Current version of notification profile {} is same as in request. New version is not created",
                            notificationProfile.getName());
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
                throw new ValidationException("Notification profile %s was concurrently modified. Retry the edit."
                        .formatted(notificationProfile.getName()));
            }
            throw e;
        }

        return notificationProfileVersion.mapToDetailDto(recipients);
    }

    /**
     * Normalizes a requested category list to its canonical form: rejects null elements with an actionable error,
     * removes duplicates, and orders by enum declaration so stored values and equality checks are
     * representation-independent. Callers keep an absent (null) field as-is -- it means "keep the current value" on
     * update and never reaches this method.
     */
    private static List<NotificationDataCategory> normalizeEventDataCategories(
            List<NotificationDataCategory> categories) {
        // Immutable lists reject null probes, so the null scan must not use contains(null).
        if (categories.stream().anyMatch(Objects::isNull)) {
            throw new ValidationException("Event data categories must not contain null entries");
        }
        return categories.isEmpty() ? List.of() : List.copyOf(EnumSet.copyOf(categories));
    }

    /**
     * The gated categories a request must be authorized for, or an empty set when no gate applies. The gate fires when
     * the resulting state has a gated category enabled and the request either adds a gated category or moves the
     * profile to another notification instance -- swapping the destination must not become an ungated route for data an
     * operator was never allowed to export. Absent (null) requested categories keep the current value (presence-aware
     * update).
     */
    private static Set<NotificationDataCategory> gatedCategoriesRequiringAuthorization(
            List<NotificationDataCategory> currentCategories, UUID currentDestination,
            List<NotificationDataCategory> requestedCategories, UUID requestedDestination) {
        List<NotificationDataCategory> resultingCategories = requestedCategories != null
                ? requestedCategories
                : currentCategories;

        Set<NotificationDataCategory> resultingGated = resultingCategories
                .stream()
                .filter(NotificationDataCategoryGate::isGated)
                .collect(Collectors.toSet());
        boolean addsGatedCategory = !new HashSet<>(currentCategories).containsAll(resultingGated);
        boolean destinationChanges = !Objects.equals(currentDestination, requestedDestination);
        return !resultingGated.isEmpty() && (addsGatedCategory || destinationChanges) ? resultingGated : Set.of();
    }

    /**
     * Applies the parent-level {@code eventDataCategories} update with presence-aware semantics: an absent (null) field
     * keeps the current value so older API clients cannot silently clear it, an empty list disables enrichment.
     * Category edits update the parent in place (through its optimistic lock) and never create a profile version.
     * Authorization happened in the orchestrator, outside this transaction.
     */
    private void applyEventDataCategories(NotificationProfile notificationProfile,
            NotificationProfileUpdateRequestDto updateRequestDto) {
        List<NotificationDataCategory> requestedCategories = updateRequestDto.getEventDataCategories();
        if (requestedCategories != null
                && !Objects.equals(notificationProfile.getEventDataCategories(), requestedCategories)) {
            notificationProfile.setEventDataCategories(requestedCategories);
            notificationProfileRepository.save(notificationProfile);
        }
    }

    /**
     * Fails fast with a not-found error for a client-supplied notification instance reference that does not exist;
     * without this check the insert would fail the foreign key and surface as a server error. The foreign key still
     * guards the race with a concurrent instance deletion.
     */
    private void validateNotificationInstanceExists(UUID notificationInstanceUuid) throws NotFoundException {
        if (notificationInstanceUuid != null
                && notificationInstanceReferenceRepository.findByUuid(notificationInstanceUuid).isEmpty()) {
            throw new NotFoundException(NotificationInstanceReference.class, notificationInstanceUuid);
        }
    }

    private static boolean isUniqueVersionViolation(DataIntegrityViolationException e) {
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException constraintViolation) {
                return NotificationProfileVersion.UNIQUE_VERSION_CONSTRAINT
                        .equalsIgnoreCase(constraintViolation.getConstraintName());
            }
        }
        return false;
    }

    private NotificationProfileDetailDto getNotificationProfileDetailDto(
            NotificationProfileVersion notificationProfileVersion) throws NotFoundException {
        return notificationProfileVersion
                .mapToDetailDto(resolveRecipients(notificationProfileVersion.getRecipientType(),
                        notificationProfileVersion.getRecipientUuids()));
    }

    // retrieve recipients info and check for existence of such object
    private List<NameAndUuidDto> resolveRecipients(RecipientType recipientType, List<UUID> recipientUuids)
            throws NotFoundException {
        List<NameAndUuidDto> recipients = new ArrayList<>();
        if (recipientUuids != null) {
            for (UUID recipientUuid : recipientUuids) {
                recipients.add(resourceObjectAssociationService.getRecipientObjectInfo(recipientType, recipientUuid));
            }
        }

        return recipients;
    }

    private boolean areVersionsEqual(NotificationProfileVersion currentVersion,
            NotificationProfileUpdateRequestDto requestDto) {
        return currentVersion.getRecipientType() == requestDto.getRecipientType()
                && Objects.equals(currentVersion.getRecipientUuids(), requestDto.getRecipientUuids())
                && Objects
                        .equals(currentVersion.getNotificationInstanceRefUuid(),
                                requestDto.getNotificationInstanceUuid())
                && currentVersion.isInternalNotification() == requestDto.isInternalNotification()
                && Objects.equals(currentVersion.getFrequency(), requestDto.getFrequency())
                && Objects.equals(currentVersion.getRepetitions(), requestDto.getRepetitions());
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return notificationProfileRepository.findResourceObject(objectUuid, NotificationProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return notificationProfileRepository.listResourceObjects(filter, NotificationProfile_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_PROFILE, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getResourceObjectInternal(uuid.getValue());
        // A notification profile has no parent, so no exclusive parent permission evaluation is needed
    }
}
