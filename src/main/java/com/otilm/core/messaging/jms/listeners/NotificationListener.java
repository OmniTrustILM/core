package com.otilm.core.messaging.jms.listeners;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.events.data.ApprovalEventData;
import com.otilm.api.model.common.events.data.CertificateActionPerformedEventData;
import com.otilm.api.model.common.events.data.CertificateDiscoveredEventData;
import com.otilm.api.model.common.events.data.CertificateEventData;
import com.otilm.api.model.common.events.data.CertificateExpiringEventData;
import com.otilm.api.model.common.events.data.CertificateNotCompliantEventData;
import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.api.model.common.events.data.CertificateStatusChangedEventData;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.common.events.data.DiscoveryFinishedEventData;
import com.otilm.api.model.common.events.data.EventData;
import com.otilm.api.model.common.events.data.InternalNotificationEventData;
import com.otilm.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.otilm.api.model.connector.notification.NotificationEventObjectDataDto;
import com.otilm.api.model.connector.notification.NotificationProviderNotifyRequestDto;
import com.otilm.api.model.connector.notification.NotificationRecipientDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.notification.NotificationSubject;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.NotificationInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.notifications.NotificationObjectDataService;
import com.otilm.core.service.notifications.NotificationSubjectResolver;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.service.writer.PendingNotificationWriter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@AllArgsConstructor
@Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
public class NotificationListener implements MessageProcessor<NotificationMessage> {

    private static final Logger logger = LoggerFactory.getLogger(NotificationListener.class);
    private static final String EMAIL_NOTIFICATION_PROVIDER_KIND = "EMAIL";
    private static final Set<Resource> OBJECT_RECIPIENT_SUBJECT_RESOURCES = Set.of(Resource.CERTIFICATE);
    private static final Set<ResourceEvent> SUBJECT_LINKED_EVENTS = EnumSet
            .of(ResourceEvent.COMMENT_CREATED, ResourceEvent.COMMENT_RESOLVED);

    private ObjectMapper mapper;
    private AttributeEngine attributeEngine;

    private NotificationInternalService notificationService;
    private TriggerInternalService triggerService;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorInternalService connectorService;
    private PendingNotificationRepository pendingNotificationRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;

    private GroupRepository groupRepository;
    private UserManagementApiClient userManagementApiClient;
    private RoleManagementApiClient roleManagementApiClient;
    private ResourceObjectAssociationService resourceObjectAssociationService;
    private TransactionHandler transactionHandler;
    private PendingNotificationWriter pendingNotificationWriter;
    private NotificationObjectDataService notificationObjectDataService;

    private static final Map<ResourceEvent, String> eventToLegacyNotificationTypeMapping = new EnumMap<>(
            ResourceEvent.class);

    static {
        eventToLegacyNotificationTypeMapping
                .put(ResourceEvent.CERTIFICATE_STATUS_CHANGED, "certificate_status_changed");
        eventToLegacyNotificationTypeMapping
                .put(ResourceEvent.CERTIFICATE_ACTION_PERFORMED, "certificate_action_performed");
        eventToLegacyNotificationTypeMapping.put(ResourceEvent.APPROVAL_REQUESTED, "approval_requested");
        eventToLegacyNotificationTypeMapping.put(ResourceEvent.APPROVAL_CLOSED, "approval_closed");
        eventToLegacyNotificationTypeMapping.put(ResourceEvent.SCHEDULED_JOB_FINISHED, "scheduled_job_completed");
    }

    @Override
    public void processMessage(NotificationMessage message) {
        // Log only identifiers, never the whole message: after the JMS round-trip `data` is an untyped map, so
        // a payload secret (e.g. a registration credential) would print in cleartext despite the DTO's toString
        // exclusion.
        logger
                .debug("Received notification message: event={} resource={} object={}", message.getEvent(),
                        message.getResource(), message.getObjectUuid());

        if (message.getNotificationProfileUuids() == null) {
            try {
                InternalNotificationOutcome outcome = sendInternalNotifications(message.getRecipients(),
                        getInternalNotificationData(message), message.getResource(), message.getObjectUuid());
                reportInternalNotificationGap(outcome,
                        "Event %s on %s %s"
                                .formatted(message.getEvent(), message.getResource(), message.getObjectUuid()),
                        message);
            } catch (Exception e) {
                logger.error("Error in internal notification: {}", e.toString());
            }
        } else {
            for (UUID notificationProfileUuid : message.getNotificationProfileUuids()) {
                try {
                    sendByNotificationProfile(notificationProfileUuid, message);
                } catch (Exception e) {
                    handleNotificationErrorWithErrorLog(
                            "Error in sending notifications based on notification profile %s: %s"
                                    .formatted(notificationProfileUuid, e.getMessage()),
                            message);
                }
            }

        }

        logger.debug("Notification message handled");
    }

    private void sendByNotificationProfile(UUID notificationProfileUuid, NotificationMessage message)
            throws NotFoundException {
        PendingNotification pendingNotification = message.getEvent().isMonitoring()
                ? pendingNotificationRepository
                        .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(notificationProfileUuid,
                                message.getResource(), message.getObjectUuid(), message.getEvent())
                : null;
        NotificationProfileVersion notificationProfileVersion = resolveProfileVersion(notificationProfileUuid,
                pendingNotification);
        if (pendingNotification == null) {
            pendingNotification = getNewPendingNotification(message, notificationProfileVersion, null);
        }

        boolean sendInternalNotifications = notificationProfileVersion.isInternalNotification()
                && (notificationProfileVersion.getRecipientType() != RecipientType.DEFAULT
                        || message.getEvent().isMonitoring());
        if (!sendInternalNotifications && notificationProfileVersion.getNotificationInstanceRefUuid() == null) {
            handleNotificationErrorWithWarnLog(
                    "Notification profile %s in event %s does not have assigned notification instance and internal notification is not enabled, notification cannot be sent."
                            .formatted(notificationProfileVersion.getNotificationProfile().getName(),
                                    message.getEvent()),
                    message);
            return;
        }

        if (!proceedWithNotifying(notificationProfileVersion, pendingNotification)) {
            logger
                    .debug("Notification suppressed for {} with UUID {} by configuration of notification profile {} for event {}. Notification sent last time at {} and was repeated {} times.",
                            pendingNotification.getResource().getLabel(), pendingNotification.getObjectUuid(),
                            notificationProfileVersion.getNotificationProfile().getName(), message.getEvent(),
                            pendingNotification.getLastSentAt(), pendingNotification.getRepetitions());
            return;
        }

        EventData eventData = convertEventDataBestEffort(message);
        NotificationSubjectResolver.SubjectRef subject = NotificationSubjectResolver
                .resolveSubject(message.getResource(), message.getObjectUuid(), eventData);
        List<NotificationRecipient> recipients = getRecipients(notificationProfileVersion.getRecipientType(),
                notificationProfileVersion.getRecipientUuids(), message, subject);

        // send external notification
        boolean notificationSent = sendExternalNotificationsForProfile(message, notificationProfileVersion, recipients,
                subject, eventData);

        // send internal notification when not Default recipient type. Default internal notifications for events are
        // sent in corresponding event handlers
        if (sendInternalNotifications) {
            try {
                NotificationSubjectResolver.SubjectRef target = internalNotificationTarget(message.getEvent(),
                        message.getResource(), message.getObjectUuid(), subject);
                InternalNotificationOutcome outcome = sendInternalNotifications(recipients,
                        getInternalNotificationData(message), target.resource(), target.objectUuid());
                notificationSent = notificationSent || outcome.notified() > 0;
                reportInternalNotificationGap(outcome, "Notification profile %s in event %s"
                        .formatted(notificationProfileVersion.getNotificationProfile().getName(), message.getEvent()),
                        message);
            } catch (ValidationException e) {
                handleNotificationErrorWithErrorLog("Error in internal notification: %s".formatted(e.toString()),
                        message);
            }
        }

        if (pendingNotification != null && notificationSent) {
            recordSuppressionState(notificationProfileUuid, message, pendingNotification.getVersion());
        }
    }

    /**
     * The profile version this send runs under: an existing suppression row pins the version that was current when its
     * monitoring stream started (frequency and repetition accounting stay consistent across profile edits); everything
     * else takes the latest version.
     */
    private NotificationProfileVersion resolveProfileVersion(UUID notificationProfileUuid,
            PendingNotification pendingNotification) throws NotFoundException {
        if (pendingNotification != null) {
            return notificationProfileVersionRepository
                    .findByNotificationProfileUuidAndVersion(notificationProfileUuid, pendingNotification.getVersion())
                    .orElseThrow(() -> new NotFoundException(NotificationProfile.class, notificationProfileUuid));
        }
        return notificationProfileVersionRepository
                .findTopByNotificationProfileUuidOrderByVersionDesc(notificationProfileUuid)
                .orElseThrow(() -> new NotFoundException(NotificationProfile.class, notificationProfileUuid));
    }

    /**
     * Records the successful delivery in the suppression row. A write failure is logged and swallowed: the notification
     * was already delivered -- to the connector, internally, or both -- so suppression state stays as-is and the next
     * occurrence may send one extra notification. Rolling anything back or reporting a delivery failure would put local
     * state behind a delivery that already happened.
     */
    private void recordSuppressionState(UUID notificationProfileUuid, NotificationMessage message, int pinnedVersion) {
        try {
            pendingNotificationWriter
                    .recordSent(notificationProfileUuid, message.getResource(), message.getObjectUuid(),
                            message.getEvent(), pinnedVersion);
        } catch (RuntimeException e) {
            logger
                    .error("Notification for profile {} event {} on {} {} was sent but recording suppression state failed",
                            notificationProfileUuid, message.getEvent(), message.getResource(), message.getObjectUuid(),
                            e);
        }
    }

    private boolean sendExternalNotificationsForProfile(NotificationMessage message,
            NotificationProfileVersion notificationProfileVersion, List<NotificationRecipient> recipients,
            NotificationSubjectResolver.SubjectRef subject, EventData eventData) {
        boolean notificationSent = false;
        if (notificationProfileVersion.getNotificationInstanceRefUuid() != null) {
            UUID notificationInstanceUUID = notificationProfileVersion.getNotificationInstanceRefUuid();
            logger
                    .debug("Sending notification message externally. Notification instance UUID: {}",
                            notificationInstanceUUID);
            NotificationEventObjectDataDto objectData = buildObjectData(message, notificationProfileVersion, eventData);
            try {
                if (!sendExternalNotifications(notificationInstanceUUID, recipients, message.getData(),
                        message.getEvent(), message.getResource(), objectRecipientResource(message, subject),
                        objectData)) {
                    // The connector still received the notification -- reported so a recipient that never resolves
                    // is visible, rather than the notification quietly reaching fewer people than configured.
                    handleNotificationErrorWithWarnLog(
                            "Notification profile %s in event %s could not prepare all of its recipients for delivery."
                                    .formatted(notificationProfileVersion.getNotificationProfile().getName(),
                                            message.getEvent()),
                            message);
                }
                logger.debug("Sending notification message externally successful.");
                notificationSent = true;
            } catch (ConnectorEntityNotFoundException e) {
                handleNotificationErrorWithWarnLog(
                        "Notification instance %s configured for notification profile %s in event %s was not found."
                                .formatted(notificationInstanceUUID,
                                        notificationProfileVersion.getNotificationProfile().getName(),
                                        message.getEvent()),
                        message);
            } catch (ValidationException e) {
                handleNotificationErrorWithWarnLog(
                        "Validation error in sending notification to connector of notification instance %s configured for notification profile %s in event %s: %s"
                                .formatted(notificationInstanceUUID,
                                        notificationProfileVersion.getNotificationProfile().getName(),
                                        message.getEvent(), e.getMessage()),
                        message);
            } catch (Exception e) {
                handleNotificationErrorWithErrorLog(
                        "Error in external notification with notification instance %s configured for notification profile %s in event %s: %s"
                                .formatted(notificationInstanceUUID,
                                        notificationProfileVersion.getNotificationProfile().getName(),
                                        message.getEvent(), e.toString()),
                        message);
            }
        }
        return notificationSent;
    }

    /**
     * Builds the enriched object data once per profile send, only when the parent profile has categories enabled -- the
     * parent field is read so a category change applies immediately, including to monitoring streams pinned to older
     * profile versions. Enrichment is best-effort: any failure yields a data-less send, never a suppressed one. The
     * result exists only in the outbound connector request; internal notifications never carry it.
     */
    private NotificationEventObjectDataDto buildObjectData(NotificationMessage message,
            NotificationProfileVersion notificationProfileVersion, EventData eventData) {
        try {
            List<NotificationDataCategory> categories = notificationProfileVersion
                    .getNotificationProfile()
                    .getEventDataCategories();
            if (categories.isEmpty()) {
                return null;
            }
            return notificationObjectDataService
                    .getObjectData(message.getEvent(), message.getResource(), message.getObjectUuid(), eventData,
                            EnumSet.copyOf(categories));
        } catch (Exception e) {
            logger
                    .warn("Notification object data could not be built for profile version {} in event {}; sending without it",
                            notificationProfileVersion.getUuid(), message.getEvent(), e);
            return null;
        }
    }

    /**
     * The typed event payload is needed only for subject resolution (approval events carry their target's coordinates
     * in it); a malformed payload therefore falls back to the event object as the subject instead of disabling every
     * enrichment category.
     */
    private EventData convertEventDataBestEffort(NotificationMessage message) {
        try {
            return getEventData(message.getEvent(), message.getData());
        } catch (Exception e) {
            logger
                    .warn("Event data of {} for {} {} could not be converted; the enrichment subject falls back to the event object: {}",
                            message.getEvent(), message.getResource(), message.getObjectUuid(), e.getMessage());
            return null;
        }
    }

    /**
     * Reports what the internal notification did not manage to do, so a recipient that never gets notified is visible
     * on trigger history rather than only in a log line. Recipients that failed are reported even when others succeeded
     * -- the external path reports its equivalent gap the same way.
     */
    private void reportInternalNotificationGap(InternalNotificationOutcome outcome, String context,
            NotificationMessage message) {
        if (outcome.failed() > 0) {
            handleNotificationErrorWithWarnLog("%s could not notify %d of its %d internal recipient(s)."
                    .formatted(context, outcome.failed(), outcome.total()), message);
        } else if (outcome.notifiedNoOne()) {
            handleNotificationErrorWithWarnLog(
                    "%s notified no one internally; its %d recipient(s) resolved to no users."
                            .formatted(context, outcome.total()),
                    message);
        }
    }

    private void handleNotificationErrorWithErrorLog(String errorMessage, NotificationMessage message) {
        logger.error(errorMessage);
        recordNotificationFailureOnTriggerHistory(errorMessage, message);
    }

    private void handleNotificationErrorWithWarnLog(String errorMessage, NotificationMessage message) {
        logger.warn(errorMessage);
        recordNotificationFailureOnTriggerHistory(errorMessage, message);
    }

    /**
     * Written in its own transaction: the listener runs without an ambient one, and the two history writes must land
     * atomically -- this record is the only durable trace of why the trigger's notification did not go out. The trigger
     * history row it references is committed well before this runs -- the notification message is dispatched from an
     * {@code AFTER_COMMIT} listener on the transaction that created it.
     */
    private void recordNotificationFailureOnTriggerHistory(String errorMessage, NotificationMessage message) {
        if (message.getTriggerHistoryUuid() == null) {
            return;
        }

        try {
            transactionHandler.runInNewTransaction(() -> {
                triggerService
                        .createTriggerHistoryRecord(message.getTriggerHistoryUuid(), null, message.getExecutionUuid(),
                                errorMessage);
                triggerService.setTriggerHistoryActionsPerformedFalse(message.getTriggerHistoryUuid());
            });
        } catch (Exception e) {
            // The last place the failure could have been recorded, so the log is all that is left.
            logger
                    .error("Could not record the notification failure on trigger history {}: {}",
                            message.getTriggerHistoryUuid(), e.getMessage(), e);
        }
    }

    private static PendingNotification getNewPendingNotification(NotificationMessage message,
            NotificationProfileVersion notificationProfileVersion, PendingNotification pendingNotification) {
        if (message.getEvent().isMonitoring() && (notificationProfileVersion.getFrequency() != null
                || notificationProfileVersion.getRepetitions() != null)) {
            pendingNotification = new PendingNotification();
            pendingNotification.setNotificationProfileUuid(notificationProfileVersion.getNotificationProfileUuid());
            pendingNotification.setVersion(notificationProfileVersion.getVersion());
            pendingNotification.setEvent(message.getEvent());
            pendingNotification.setResource(message.getResource());
            pendingNotification.setObjectUuid(message.getObjectUuid());
        }
        return pendingNotification;
    }

    private boolean proceedWithNotifying(NotificationProfileVersion notificationProfileVersion,
            PendingNotification pendingNotification) {
        if (pendingNotification == null) {
            return true;
        }

        OffsetDateTime now = OffsetDateTime.now();
        return (notificationProfileVersion.getFrequency() == null || pendingNotification.getLastSentAt() == null
                || Duration
                        .between(pendingNotification.getLastSentAt(), now)
                        .compareTo(notificationProfileVersion.getFrequency()) > 0)
                && (notificationProfileVersion.getRepetitions() == null
                        || pendingNotification.getRepetitions() < notificationProfileVersion.getRepetitions());
    }

    private List<NotificationRecipient> getRecipients(RecipientType recipientType, List<UUID> recipientUuids,
            NotificationMessage message, NotificationSubjectResolver.SubjectRef subject) {
        if (recipientType == RecipientType.OBJECT) {
            return List.of(new NotificationRecipient(RecipientType.OBJECT, objectRecipientUuid(message, subject)));
        }

        if (recipientType != RecipientType.OWNER && recipientType != RecipientType.DEFAULT) {
            return explicitRecipients(recipientType, recipientUuids);
        }

        if (recipientType == RecipientType.OWNER) {
            // The subject's owner, not the event object's: for approval events this is the owner
            // of the object awaiting approval -- the approval record itself has no owner.
            NameAndUuidDto ownerInfo = resourceObjectAssociationService
                    .getOwner(subject.resource(), subject.objectUuid());
            if (ownerInfo == null) {
                return List.of();
            }
            return List.of(new NotificationRecipient(RecipientType.USER, UUID.fromString(ownerInfo.getUuid())));
        }

        // Defaults resolve against the subject for the same reason OWNER does: comment events carry the comment,
        // but their natural audience belongs to the host object.
        return getDefaultRecipients(message.getEvent(), message.getData(), subject.resource(), subject.objectUuid());
    }

    /**
     * The object an OBJECT recipient resolves its mapped attributes from. Subject redirection is whitelisted per
     * resource, mirroring the content-exporter philosophy: the mapped-attribute channel carries raw attribute content
     * with neither the enrichment protection filters nor a category gate, and approval targets are polymorphic -- a
     * secret's attribute content must not become exportable as a side effect of recipient resolution. Non-whitelisted
     * subjects resolve against the event object.
     */
    private static UUID objectRecipientUuid(NotificationMessage message,
            NotificationSubjectResolver.SubjectRef subject) {
        return OBJECT_RECIPIENT_SUBJECT_RESOURCES.contains(subject.resource())
                ? subject.objectUuid()
                : message.getObjectUuid();
    }

    private static Resource objectRecipientResource(NotificationMessage message,
            NotificationSubjectResolver.SubjectRef subject) {
        return OBJECT_RECIPIENT_SUBJECT_RESOURCES.contains(subject.resource())
                ? subject.resource()
                : message.getResource();
    }

    /**
     * Maps an explicit recipient type (USER / GROUP / ROLE) to its recipients. A misconfigured profile may carry a null
     * or empty UUID list; return no recipients rather than dereferencing null. The caller logs the empty outcome with
     * profile and event context.
     */
    static List<NotificationRecipient> explicitRecipients(RecipientType recipientType, List<UUID> recipientUuids) {
        if (recipientUuids == null || recipientUuids.isEmpty()) {
            return List.of();
        }
        return recipientUuids.stream().map(uuid -> new NotificationRecipient(recipientType, uuid)).toList();
    }

    /**
     * The notification targets the host object, which is the page that exists; naming the comment as well is what lets
     * the reader be taken to it rather than to the top of a busy thread list. The body stays out: the notification
     * points at the comment, it does not mirror user-authored text.
     */
    private static InternalNotificationEventData commentNotification(String text, CommentEventData data) {
        InternalNotificationEventData notificationData = new InternalNotificationEventData(text, null);
        notificationData.setSubjectObjectType(Resource.COMMENT);
        notificationData.setSubjectObjectIdentification(uuidText(data.getCommentUuid()));
        notificationData.setSubjectParentIdentification(uuidText(data.getParentUuid()));
        return notificationData;
    }

    private static String uuidText(UUID uuid) {
        return uuid == null ? null : uuid.toString();
    }

    private static NotificationSubject subjectOf(InternalNotificationEventData notificationData) {
        if (notificationData.getSubjectObjectType() == null) {
            return null;
        }
        return new NotificationSubject(notificationData.getSubjectObjectType(),
                notificationData.getSubjectObjectIdentification(), notificationData.getSubjectParentIdentification());
    }

    /**
     * Which object the persisted notification points the reader at. Almost every event names the record the reader acts
     * on -- an approval notification must open the approval, not the object awaiting it -- so the message's own
     * coordinates win. A comment has no page of its own, so its notification points at the host object instead,
     * matching what the comment handlers publish for their follow-ups.
     */
    static NotificationSubjectResolver.SubjectRef internalNotificationTarget(ResourceEvent event,
            Resource messageResource, UUID messageObjectUuid, NotificationSubjectResolver.SubjectRef subject) {
        return SUBJECT_LINKED_EVENTS.contains(event)
                ? subject
                : new NotificationSubjectResolver.SubjectRef(messageResource, messageObjectUuid);
    }

    List<NotificationRecipient> getDefaultRecipients(ResourceEvent event, Object data, Resource resource,
            UUID objectUuid) {
        List<NotificationRecipient> recipients = new ArrayList<>();
        switch (event) {
            case CERTIFICATE_STATUS_CHANGED, CERTIFICATE_ACTION_PERFORMED, CERTIFICATE_EXPIRING,
                    CERTIFICATE_NOT_COMPLIANT, CERTIFICATE_UPLOADED, COMMENT_CREATED, COMMENT_RESOLVED -> {
                NameAndUuidDto ownerInfo = resourceObjectAssociationService.getOwner(resource, objectUuid);
                if (ownerInfo != null) {
                    recipients.add(new NotificationRecipient(RecipientType.USER, UUID.fromString(ownerInfo.getUuid())));
                }

                for (UUID groupUuid : resourceObjectAssociationService.getGroupUuids(resource, objectUuid)) {
                    recipients.add(new NotificationRecipient(RecipientType.GROUP, groupUuid));
                }
            }
            case CERTIFICATE_DISCOVERED -> {
                CertificateDiscoveredEventData eventData = (CertificateDiscoveredEventData) getEventData(event, data);
                if (eventData.getDiscoveryUserUuid() != null) {
                    recipients.add(new NotificationRecipient(RecipientType.USER, eventData.getDiscoveryUserUuid()));
                }
            }
            case DISCOVERY_FINISHED -> {
                DiscoveryFinishedEventData eventData = (DiscoveryFinishedEventData) getEventData(event, data);
                if (eventData.getDiscoveryUserUuid() != null) {
                    recipients.add(new NotificationRecipient(RecipientType.USER, eventData.getDiscoveryUserUuid()));
                }
            }
            case APPROVAL_REQUESTED -> {
                ApprovalEventData eventData = (ApprovalEventData) getEventData(event, data);
                recipients.add(new NotificationRecipient(eventData.getRecipientType(), eventData.getRecipientUuid()));
            }
            case APPROVAL_CLOSED -> {
                ApprovalEventData eventData = (ApprovalEventData) getEventData(event, data);
                recipients.add(new NotificationRecipient(RecipientType.USER, eventData.getCreatorUuid()));
            }
            case SCHEDULED_JOB_FINISHED -> {
                ScheduledJobFinishedEventData eventData = (ScheduledJobFinishedEventData) getEventData(event, data);
                if (eventData.getUserUuid() != null) {
                    recipients.add(new NotificationRecipient(RecipientType.USER, eventData.getUserUuid()));
                }
            }
            case CERTIFICATE_REGISTERED -> {
                // Owner only by default (no groups) — a credential-bearing event; a profile can override.
                NameAndUuidDto ownerInfo = resourceObjectAssociationService.getOwner(resource, objectUuid);
                if (ownerInfo != null) {
                    recipients.add(new NotificationRecipient(RecipientType.USER, UUID.fromString(ownerInfo.getUuid())));
                }
            }
            // Events without a natural default audience resolve to nobody; the profile has to name recipients.
            default -> {
            }
        }

        return recipients;
    }

    /**
     * Whether every named recipient was prepared for delivery. The notification is handed to the connector either way:
     * only the provider knows whether it can deliver without recipients -- a webhook posts to the URL on its own
     * instance and ignores them, while an e-mail provider has no address and rejects the request, saying so. Deciding
     * that here would mean guessing from the instance's kind, which is a string the connector chooses, and guessing
     * "cannot deliver" wrongly loses the notification silently.
     *
     * @return false when some named recipient could not be prepared, so the caller can report the gap.
     */
    private boolean sendExternalNotifications(UUID notificationInstanceUUID, List<NotificationRecipient> recipients,
            Object notificationData, ResourceEvent event, Resource resource, Resource objectRecipientResource,
            NotificationEventObjectDataDto objectData)
            throws ConnectorException, ValidationException, NotFoundException {
        // Fetch-join the mapped attributes: the listener runs without an ambient transaction, so the
        // entity is detached the moment the repository call returns and lazy loading would fail.
        NotificationInstanceReference notificationInstanceReference = notificationInstanceReferenceRepository
                .findWithMappedAttributesByUuid(notificationInstanceUUID)
                .orElseThrow(
                        () -> new NotFoundException(NotificationInstanceReference.class, notificationInstanceUUID));
        if (notificationInstanceReference.getConnectorUuid() == null) {
            throw new ValidationException("Notification instance does not have assigned connector");
        }

        List<DataAttribute> mappingAttributes;
        ApiClientConnectorInfo connector = connectorService
                .getConnectorForApiClient(notificationInstanceReference.getConnectorUuid());
        try {
            mappingAttributes = connectorApiFactory
                    .getNotificationInstanceApiClient(connector)
                    .listMappingAttributes(connector, notificationInstanceReference.getKind());
        } catch (ConnectorException e) {
            logger.error("Cannot retrieve mapping attributes from connector: {}", e.getMessage());
            throw e;
        }

        List<NotificationRecipientDto> recipientsDto = new ArrayList<>();
        int skippedByDesign = 0; // NONE recipients resolve to no delivery DTO on purpose, not a gap to report
        for (NotificationRecipient recipient : recipients) {
            logger
                    .debug("Processing recipient {} of type {}.", recipient.getRecipientUuid(),
                            recipient.getRecipientType());
            try {
                // construct recipient DTO
                // The OBJECT recipient's label must name the resource its mapped attributes resolve from.
                NotificationRecipientDto recipientDto = constructNotificationRecipientDto(recipient,
                        notificationInstanceReference.getKind(), objectRecipientResource);
                if (recipientDto == null) {
                    // this should happen only in case of recipient type NONE
                    ++skippedByDesign;
                    continue;
                }

                Resource customAttributeResource = recipient.getRecipientType() == RecipientType.OBJECT
                        ? objectRecipientResource
                        : recipient.getRecipientType().getRecipientResource();
                // Unauthenticated lookup is correct here, since the access to the custom attributes has been resolved
                // when defining mapping attributes.
                List<ResponseAttribute> recipientCustomAttributes = attributeEngine
                        .getObjectCustomAttributesContentForSystemContext(customAttributeResource,
                                recipient.getRecipientUuid());
                // prepare mapped attributes
                List<RequestAttribute> mappedAttributes = getMappedAttributes(notificationInstanceReference,
                        mappingAttributes, recipientCustomAttributes);
                if (recipient.getRecipientType() == RecipientType.OBJECT && mappedAttributes.isEmpty()) {
                    logger
                            .warn("Notification recipient with OBJECT type does not have any mapped attributes resolved, notification cannot be sent for the OBJECT recipient ({} object with UUID {}).",
                                    customAttributeResource.getLabel(), recipient.getRecipientUuid());
                    continue;
                }
                recipientDto.setMappedAttributes(mappedAttributes);
                recipientsDto.add(recipientDto);
            } catch (Exception e) {
                logger
                        .warn("{} with UUID {} was not found or retrieval of its attributes failed: {}. Notification was not sent for this recipient.",
                                recipient.getRecipientType().getLabel(), recipient.getRecipientUuid(), e.getMessage());
            }
        }

        NotificationProviderNotifyRequestDto notificationProviderNotifyRequestDto = new NotificationProviderNotifyRequestDto();
        notificationProviderNotifyRequestDto.setNotificationData(notificationData);
        notificationProviderNotifyRequestDto.setResource(resource);
        notificationProviderNotifyRequestDto.setEvent(event);
        notificationProviderNotifyRequestDto
                .setEventType(eventToLegacyNotificationTypeMapping.getOrDefault(event, "other")); // legacy
        notificationProviderNotifyRequestDto.setRecipients(recipientsDto);
        notificationProviderNotifyRequestDto.setObjectData(objectData);

        try {
            connectorApiFactory
                    .getNotificationInstanceApiClient(connector)
                    .sendNotification(connector, notificationInstanceReference.getNotificationInstanceUuid().toString(),
                            notificationProviderNotifyRequestDto);
        } catch (ConnectorException e) {
            logger.error("Cannot send notification to connector: {}", e.getMessage());
            throw e;
        }
        return recipientsDto.size() + skippedByDesign == recipients.size();
    }

    private NotificationRecipientDto constructNotificationRecipientDto(NotificationRecipient recipient,
            String notificationProviderKind, Resource resource) {
        NotificationRecipientDto recipientDto;
        switch (recipient.getRecipientType()) {
            case USER -> {
                UserDetailDto userDetailDto = userManagementApiClient
                        .getUserDetail(recipient.getRecipientUuid().toString());
                recipientDto = new NotificationRecipientDto();
                recipientDto.setEmail(userDetailDto.getEmail());
                recipientDto.setName(userDetailDto.getUsername());
            }
            case ROLE -> {
                RoleDetailDto roleDetailDto = roleManagementApiClient
                        .getRoleDetail(recipient.getRecipientUuid().toString());
                String email = roleDetailDto.getEmail();
                if (notificationProviderKind.equals(EMAIL_NOTIFICATION_PROVIDER_KIND)
                        && (email == null || email.isBlank())) {
                    throw new NotSupportedException("Role does not have specified email");
                }
                recipientDto = new NotificationRecipientDto();
                recipientDto.setEmail(email);
                recipientDto.setName(roleDetailDto.getName());
            }
            case GROUP -> {
                Group group = groupRepository.findByUuid(recipient.getRecipientUuid()).orElseThrow();
                String email = group.getEmail();
                if (notificationProviderKind.equals(EMAIL_NOTIFICATION_PROVIDER_KIND)
                        && (email == null || email.isBlank())) {
                    throw new NotSupportedException("Group does not have specified email");
                }
                recipientDto = new NotificationRecipientDto();
                recipientDto.setName(group.getName());
                recipientDto.setEmail(email);
            }
            case NONE -> {
                if (notificationProviderKind.equals(EMAIL_NOTIFICATION_PROVIDER_KIND)) {
                    throw new NotSupportedException("Notification recipient type None is not supported for kind "
                            + EMAIL_NOTIFICATION_PROVIDER_KIND);
                }

                recipientDto = null;
            }
            case OBJECT -> {
                // The connector resolves contact details via mapped attributes — no email to set here
                recipientDto = new NotificationRecipientDto();
                recipientDto
                        .setName("Object recipient for %s with object UUID %s"
                                .formatted(resource.getLabel(), recipient.getRecipientUuid()));
            }
            default -> throw new NotSupportedException("Notification recipient type %s is not supported"
                    .formatted(recipient.getRecipientType().getLabel()));
        }
        return recipientDto;
    }

    private List<RequestAttribute> getMappedAttributes(NotificationInstanceReference notificationInstanceReference,
            List<DataAttribute> mappingAttributes, List<ResponseAttribute> recipientCustomAttributes)
            throws ValidationException {
        List<RequestAttribute> mappedAttributes = new ArrayList<>();
        HashMap<String, ResponseAttribute> mappedContent = new HashMap<>();
        for (NotificationInstanceMappedAttributes mappedAttribute : notificationInstanceReference
                .getMappedAttributes()) {
            Optional<ResponseAttribute> recipientCustomAttribute = recipientCustomAttributes
                    .stream()
                    .filter(c -> c.getUuid().equals(mappedAttribute.getAttributeDefinitionUuid()))
                    .findFirst();
            recipientCustomAttribute
                    .ifPresent(responseAttributeDto -> mappedContent
                            .put(mappedAttribute.getMappingAttributeUuid().toString(), responseAttributeDto));
        }

        for (DataAttribute mappingAttribute : mappingAttributes) {
            ResponseAttribute recipientCustomAttribute = mappedContent.get(mappingAttribute.getUuid());

            if (recipientCustomAttribute == null) {
                if (mappingAttribute.getProperties().isRequired()) {
                    throw new ValidationException(String
                            .format("Missing mapping attribute %s with UUID %s in recipient custom attributes.",
                                    mappingAttribute.getName(), mappingAttribute.getUuid()));
                }
                continue;
            }

            if (!mappingAttribute.getContentType().equals(recipientCustomAttribute.getContentType())) {
                throw new ValidationException(String
                        .format("Mapped custom attribute %s with UUID %s has different content type (%s) as mapping attribute %s with UUID %s (%s).",
                                recipientCustomAttribute.getName(), recipientCustomAttribute.getUuid(),
                                recipientCustomAttribute.getContentType().getLabel(), mappingAttribute.getName(),
                                mappingAttribute.getUuid(), mappingAttribute.getContentType().getLabel()));
            }

            RequestAttribute requestAttribute = AttributeVersionHelper
                    .getRequestAttribute(UUID.fromString(mappingAttribute.getUuid()), mappingAttribute.getName(),
                            recipientCustomAttribute.getContent(), mappingAttribute.getContentType(),
                            mappingAttribute.getVersion());
            mappedAttributes.add(requestAttribute);
        }

        return mappedAttributes;
    }

    /**
     * What became of each recipient of one event. A recipient that resolved to no users is neither notified nor failed
     * -- an empty group is configuration, while a failure is something the operator has to act on -- so the two are
     * counted apart and reported differently.
     */
    private record InternalNotificationOutcome(int notified, int failed, int total) {
        boolean notifiedNoOne() {
            return notified == 0 && total > 0;
        }
    }

    private InternalNotificationOutcome sendInternalNotifications(List<NotificationRecipient> recipients,
            InternalNotificationEventData notificationData, Resource resource, UUID objectUuid) {
        logger
                .debug("Sending internal notification. Message: {}. Detail: {}", notificationData.getText(),
                        notificationData.getDetail());
        int notified = 0;
        int failed = 0;
        for (NotificationRecipient recipient : recipients) {
            try {
                // Each recipient commits on its own: the listener runs without an ambient transaction, so
                // every notification-service call opens and commits its own short transaction.
                if (createInternalNotification(recipient, notificationData, resource, objectUuid) != null) {
                    ++notified;
                }
            } catch (Exception e) {
                // Recipients are independent, so one that cannot be notified must not cost the rest their notification.
                ++failed;
                logger
                        .warn("Internal notification could not be created for {} with UUID {}: {}",
                                recipient.getRecipientType().getLabel(), recipient.getRecipientUuid(), e.getMessage());
            }
        }
        return new InternalNotificationOutcome(notified, failed, recipients.size());
    }

    /**
     * @return the created notification, or {@code null} when the recipient resolved to no users -- a group or role with
     * no members, which is configuration rather than a failure.
     */
    private NotificationDto createInternalNotification(NotificationRecipient recipient,
            InternalNotificationEventData notificationData, Resource resource, UUID objectUuid) {
        String targetUuid = objectUuid != null ? objectUuid.toString() : null;
        String recipientUuid = recipient.getRecipientUuid().toString();
        NotificationSubject subject = subjectOf(notificationData);
        return switch (recipient.getRecipientType()) {
            case USER -> notificationService
                    .createNotificationForUser(notificationData.getText(), notificationData.getDetail(), recipientUuid,
                            resource, targetUuid, subject);
            case ROLE -> notificationService
                    .createNotificationForRole(notificationData.getText(), notificationData.getDetail(), recipientUuid,
                            resource, targetUuid, subject);
            case GROUP -> notificationService
                    .createNotificationForGroup(notificationData.getText(), notificationData.getDetail(), recipientUuid,
                            resource, targetUuid, subject);
            default -> throw new ValidationException(
                    "Unhandled recipient type for internal notification: " + recipient.getRecipientType());
        };
    }

    private InternalNotificationEventData getInternalNotificationData(NotificationMessage message)
            throws ValidationException {
        EventData eventData = getEventData(message.getEvent(), message.getData());
        if (message.getEvent() == null) {
            return (InternalNotificationEventData) eventData;
        }

        return switch (message.getEvent()) {
            case CERTIFICATE_STATUS_CHANGED -> {
                CertificateStatusChangedEventData data = (CertificateStatusChangedEventData) eventData;
                yield new InternalNotificationEventData(
                        "Certificate validation status changed from %s to %s for certificate identified as '%s' with serial number '%s' issued by '%s'"
                                .formatted(data.getOldStatus(), data.getNewStatus(), data.getSubjectDn(),
                                        data.getSerialNumber(), data.getIssuerDn()),
                        null);
            }
            case CERTIFICATE_ACTION_PERFORMED -> {
                CertificateActionPerformedEventData data = (CertificateActionPerformedEventData) eventData;
                boolean failed = data.getErrorMessage() != null;
                yield new InternalNotificationEventData(
                        "Certificate action %s %s for certificate identified as '%s'"
                                .formatted(data.getAction(), failed ? "failed" : "successful", data.getSubjectDn()),
                        failed
                                ? "Error message: " + data.getErrorMessage()
                                : "Certificate serial number '%s' issued by '%s'"
                                        .formatted(data.getSerialNumber(), data.getIssuerDn()));
            }
            case CERTIFICATE_DISCOVERED -> {
                CertificateDiscoveredEventData data = (CertificateDiscoveredEventData) eventData;
                yield new InternalNotificationEventData(
                        "Certificate identified as '%s' with serial number '%s' issued by '%s' discovered by '%s' discovery"
                                .formatted(data.getSubjectDn(), data.getSerialNumber(), data.getIssuerDn(),
                                        data.getDiscoveryName()),
                        "Discovery Connector: %s"
                                .formatted(data.getDiscoveryConnectorName() == null
                                        ? data.getDiscoveryConnectorUuid()
                                        : data.getDiscoveryConnectorName()));
            }

            case CERTIFICATE_EXPIRING -> {
                CertificateExpiringEventData data = (CertificateExpiringEventData) eventData;
                yield new InternalNotificationEventData(
                        "Certificate identified as '%s' with serial number '%s' issued by '%s' is expiring on %s"
                                .formatted(data.getSubjectDn(), data.getSerialNumber(), data.getIssuerDn(),
                                        data.getExpiresAt()),
                        null);
            }
            case CERTIFICATE_NOT_COMPLIANT -> {
                CertificateNotCompliantEventData data = (CertificateNotCompliantEventData) eventData;
                yield new InternalNotificationEventData(
                        "Certificate identified as '%s' with serial number '%s' issued by '%s' is not compliant"
                                .formatted(data.getSubjectDn(), data.getSerialNumber(), data.getIssuerDn()),
                        null);
            }
            case CERTIFICATE_UPLOADED -> {
                CertificateEventData data = (CertificateEventData) eventData;
                yield new InternalNotificationEventData(
                        "Certificate identified as '%s' with serial number '%s' issued by '%s' has been uploaded."
                                .formatted(data.getSubjectDn(), data.getSerialNumber(), data.getIssuerDn()),
                        null);
            }
            case DISCOVERY_FINISHED -> {
                DiscoveryFinishedEventData data = (DiscoveryFinishedEventData) eventData;
                yield new InternalNotificationEventData(
                        "Discovery %s has finished with status %s and discovered %d certificates"
                                .formatted(data.getDiscoveryName(), data.getDiscoveryStatus().getLabel(),
                                        data.getTotalCertificateDiscovered()),
                        data.getDiscoveryMessage());
            }
            case APPROVAL_REQUESTED -> {
                ApprovalEventData data = (ApprovalEventData) eventData;
                yield new InternalNotificationEventData("Request %s for %s from %s is waiting to be approved until %s"
                        .formatted(data.getApprovalUuid(), data.getObjectUuid(), data.getCreatorUsername(),
                                data.getExpiryAt()),
                        getApprovalNotificationDetail(data));
            }
            case APPROVAL_CLOSED -> {
                ApprovalEventData data = (ApprovalEventData) eventData;
                yield new InternalNotificationEventData("Request %s for %s from %s is %s"
                        .formatted(data.getApprovalUuid(), data.getObjectUuid(), data.getCreatorUsername(),
                                data.getStatus().getLabel()),
                        getApprovalNotificationDetail(data));
            }
            case SCHEDULED_JOB_FINISHED -> {
                ScheduledJobFinishedEventData data = (ScheduledJobFinishedEventData) eventData;
                yield new InternalNotificationEventData("%s scheduled task has finished for %s with result %s"
                        .formatted(data.getJobType(), data.getJobName(), data.getStatus()), null);
            }
            // The comment body stays out of the persisted notification on purpose: the notification points at
            // the thread, it does not mirror user-authored text.
            case COMMENT_CREATED -> {
                CommentEventData data = (CommentEventData) eventData;
                yield commentNotification("%s %s on %s '%s'"
                        .formatted(data.getAuthorUsername(),
                                data.getParentUuid() == null ? "commented" : "replied to a comment thread",
                                data.getResource().getLabel(), data.getObjectName()),
                        data);
            }
            case COMMENT_RESOLVED -> {
                CommentEventData data = (CommentEventData) eventData;
                yield commentNotification("%s %s a comment thread on %s '%s'"
                        .formatted(data.getResolvedByUsername(),
                                Boolean.TRUE.equals(data.getResolved()) ? "resolved" : "reopened",
                                data.getResource().getLabel(), data.getObjectName()),
                        data);
            }
            case CERTIFICATE_REGISTERED -> {
                CertificateRegisteredEventData data = (CertificateRegisteredEventData) eventData;
                // Informational only — the credential is delivered on the external-provider path and must never be
                // written here (this text/detail is persisted to the notifications table).
                yield new InternalNotificationEventData(
                        "Certificate identified as '%s' has been pre-registered and is awaiting issuance completion"
                                .formatted(data.getSubjectDn()),
                        data.getCompletionDeadline() == null
                                ? null
                                : "Issuance must be completed by %s".formatted(data.getCompletionDeadline()));
            }
        };
    }

    private EventData getEventData(ResourceEvent event, Object data) {
        Class<? extends EventData> dataClazz = event == null
                ? InternalNotificationEventData.class
                : event.getEventData();

        EventData eventData;
        try {
            eventData = mapper.convertValue(data, dataClazz);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    "NotificationMessage for internal notification contains invalid data. Expected: "
                            + dataClazz.getName());
        }

        return eventData;
    }

    private String getApprovalNotificationDetail(ApprovalEventData approvalData) {
        return String
                .format("Approval profile name: %s, Resource: %s, Resource action: %s, Object UUID: %s",
                        approvalData.getApprovalProfileName(), approvalData.getResource().getLabel(),
                        approvalData.getResourceAction(), approvalData.getObjectUuid());
    }

}
