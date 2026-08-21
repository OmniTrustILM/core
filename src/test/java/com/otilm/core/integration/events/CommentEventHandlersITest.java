package com.otilm.core.integration.events;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ActionRequestDto;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.api.model.core.workflows.ConditionRequestDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.RuleRequestDto;
import com.otilm.api.model.core.workflows.TriggerRequestDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.notifications.Notification;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationRepository;
import com.otilm.core.dao.repository.workflows.EventHistoryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.handlers.CommentCreatedEventHandler;
import com.otilm.core.events.handlers.CommentResolvedEventHandler;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.service.RuleExternalService;
import com.otilm.core.service.TriggerExternalService;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.filter.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CommentEventHandlersITest extends BaseSpringBootTest {

    @Autowired
    private CommentCreatedEventHandler commentCreatedEventHandler;
    @Autowired
    private CommentResolvedEventHandler commentResolvedEventHandler;
    @Autowired
    private NotificationListener notificationListener;
    @Autowired
    private ProducerMocks.RecordedNotificationMessages recordedMessages;

    @Autowired
    private CommentRepository commentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private GroupAssociationRepository groupAssociationRepository;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @Autowired
    private NotificationRepository notificationRepository;
    @Autowired
    private EventHistoryRepository eventHistoryRepository;

    @Autowired
    private NotificationProfileExternalService notificationProfileService;
    @Autowired
    private ActionExternalService actionService;
    @Autowired
    private TriggerExternalService triggerService;
    @Autowired
    private RuleExternalService ruleService;

    private WireMockServer mockServer;

    private UUID hostUuid;
    private UUID actorUuid;

    @BeforeEach
    void setUp() {
        recordedMessages.clear();
        actorUuid = UUID.randomUUID();

        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        hostUuid = raProfileRepository.save(raProfile).getUuid();

        mockServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        mockServer.start();
        WireMock.configureFor("localhost", WireMockPorts.AUTH_SERVICE);
        mockAuthResponses();
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    /** Impersonation of the trigger-association owner authenticates against the auth service. */
    private void mockAuthResponses() {
        AuthServiceWireMockStubs.stubImpersonation(mockServer, UUID.randomUUID(), "tst-association-owner");
    }

    private Comment saveComment(UUID objectUuid, UUID parentUuid, UUID authorUuid, String body) {
        Comment comment = new Comment();
        comment.setResource(Resource.RA_PROFILE);
        comment.setObjectUuid(objectUuid);
        comment.setParentUuid(parentUuid);
        comment.setAuthorUuid(authorUuid);
        comment.setAuthorUsername("tst-user");
        comment.setBody(body);
        return commentRepository.saveAndFlush(comment);
    }

    private EventMessage eventMessage(ResourceEvent event, Comment comment, Boolean resolved) {
        CommentEventData data = new CommentEventData();
        data.setCommentUuid(comment.getUuid());
        data.setParentUuid(comment.getParentUuid());
        data.setResource(comment.getResource());
        data.setObjectUuid(comment.getObjectUuid());
        data.setObjectName("tst-ra-profile");
        data.setAuthorUuid(comment.getAuthorUuid());
        data.setAuthorUsername(comment.getAuthorUsername());
        data.setCreatedAt(OffsetDateTime.now());
        data.setBody(comment.getBody());
        if (resolved != null) {
            data.setResolved(resolved);
            data.setResolvedByUuid(actorUuid);
            data.setResolvedByUsername("tst-actor");
            data.setResolvedAt(OffsetDateTime.now());
        }
        return new EventMessage(event, Resource.COMMENT, comment.getUuid(), null, null, data, actorUuid, null);
    }

    private UUID groupWithHostMembership(UUID objectUuid) {
        Group group = new Group();
        group.setName("tst-group-" + UUID.randomUUID());
        groupRepository.save(group);

        GroupAssociation association = new GroupAssociation();
        association.setResource(Resource.RA_PROFILE);
        association.setObjectUuid(objectUuid);
        association.setGroupUuid(group.getUuid());
        groupAssociationRepository.save(association);
        return group.getUuid();
    }

    private UUID bindProfileTrigger(ResourceEvent event, Resource associationResource, UUID associationObjectUuid)
            throws AlreadyExistException, NotFoundException {
        return bindProfileTrigger(event, associationResource, associationObjectUuid, null);
    }

    private UUID bindProfileTrigger(ResourceEvent event, Resource associationResource, UUID associationObjectUuid,
            String ruleUuid) throws AlreadyExistException, NotFoundException {
        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("tst-profile-" + UUID.randomUUID().toString().substring(0, 8));
        profileRequest.setRecipientType(RecipientType.USER);
        profileRequest.setRecipientUuids(List.of(UUID.randomUUID()));
        profileRequest.setRepetitions(1);
        profileRequest.setInternalNotification(true);
        UUID profileUuid = UUID
                .fromString(notificationProfileService.createNotificationProfile(profileRequest).getUuid());

        ExecutionItemRequestDto executionItemRequest = new ExecutionItemRequestDto();
        executionItemRequest.setNotificationProfileUuid(profileUuid.toString());
        ExecutionRequestDto executionRequest = new ExecutionRequestDto();
        executionRequest.setName("tst-execution-" + UUID.randomUUID().toString().substring(0, 8));
        executionRequest.setResource(Resource.COMMENT);
        executionRequest.setType(ExecutionType.SEND_NOTIFICATION);
        executionRequest.setItems(List.of(executionItemRequest));
        String executionUuid = actionService.createExecution(executionRequest).getUuid();

        ActionRequestDto actionRequest = new ActionRequestDto();
        actionRequest.setName("tst-action-" + UUID.randomUUID().toString().substring(0, 8));
        actionRequest.setResource(Resource.COMMENT);
        actionRequest.setExecutionsUuids(List.of(executionUuid));
        String actionUuid = actionService.createAction(actionRequest).getUuid();

        TriggerRequestDto triggerRequest = new TriggerRequestDto();
        triggerRequest.setName("tst-trigger-" + UUID.randomUUID().toString().substring(0, 8));
        triggerRequest.setResource(Resource.COMMENT);
        triggerRequest.setType(TriggerType.EVENT);
        triggerRequest.setEvent(event);
        triggerRequest.setActionsUuids(List.of(actionUuid));
        if (ruleUuid != null) {
            triggerRequest.setRulesUuids(List.of(ruleUuid));
        }
        UUID triggerUuid = UUID.fromString(triggerService.createTrigger(triggerRequest).getUuid());

        triggerService
                .createTriggerAssociations(event, associationResource, associationObjectUuid, List.of(triggerUuid),
                        false);
        return profileUuid;
    }

    /** Roots carry no parent, so a "Parent Comment is empty" condition scopes the trigger to thread roots. */
    private String rootsOnlyRule() throws AlreadyExistException, NotFoundException {
        ConditionItemRequestDto conditionItemRequest = new ConditionItemRequestDto();
        conditionItemRequest.setFieldSource(FilterFieldSource.PROPERTY);
        conditionItemRequest.setFieldIdentifier(FilterField.COMMENT_PARENT.name());
        conditionItemRequest.setOperator(FilterConditionOperator.EMPTY);

        ConditionRequestDto conditionRequest = new ConditionRequestDto();
        conditionRequest.setName("tst-condition-" + UUID.randomUUID().toString().substring(0, 8));
        conditionRequest.setResource(Resource.COMMENT);
        conditionRequest.setType(ConditionType.CHECK_FIELD);
        conditionRequest.setItems(List.of(conditionItemRequest));
        String conditionUuid = ruleService.createCondition(conditionRequest).getUuid();

        RuleRequestDto ruleRequest = new RuleRequestDto();
        ruleRequest.setName("tst-rule-" + UUID.randomUUID().toString().substring(0, 8));
        ruleRequest.setResource(Resource.COMMENT);
        ruleRequest.setConditionsUuids(List.of(conditionUuid));
        return ruleService.createRule(ruleRequest).getUuid();
    }

    private List<NotificationMessage> profileDrivenMessages() {
        return recordedMessages.messages().stream().filter(m -> m.getNotificationProfileUuids() != null).toList();
    }

    private List<NotificationMessage> followUpMessages() {
        return recordedMessages.messages().stream().filter(m -> m.getNotificationProfileUuids() == null).toList();
    }

    @Test
    void groupScopedProfileFiresOnlyForObjectsInTheGroup() throws Exception {
        UUID groupUuid = groupWithHostMembership(hostUuid);
        UUID profileUuid = bindProfileTrigger(ResourceEvent.COMMENT_CREATED, Resource.GROUP, groupUuid);

        Comment inGroup = saveComment(hostUuid, null, actorUuid, "comment in group");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, inGroup, null));

        assertThat(profileDrivenMessages())
                .anySatisfy(message -> assertThat(message.getNotificationProfileUuids()).contains(profileUuid));
        assertThat(eventHistoryRepository.findAll()).anySatisfy(history -> {
            assertThat(history.getResource()).isEqualTo(Resource.GROUP);
            assertThat(history.getResourceUuid()).isEqualTo(groupUuid);
        });

        recordedMessages.clear();
        RaProfile outside = new RaProfile();
        outside.setName("tst-ra-profile-outside");
        UUID outsideUuid = raProfileRepository.save(outside).getUuid();
        Comment outsideComment = saveComment(outsideUuid, null, actorUuid, "comment outside group");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, outsideComment, null));

        assertThat(profileDrivenMessages()).isEmpty();
    }

    @Test
    void globallyBoundProfileDeliversOnResolve() throws Exception {
        UUID profileUuid = bindProfileTrigger(ResourceEvent.COMMENT_RESOLVED, null, null);

        Comment root = saveComment(hostUuid, null, UUID.randomUUID(), "resolve me");
        commentResolvedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_RESOLVED, root, true));

        List<NotificationMessage> profileMessages = profileDrivenMessages();
        assertThat(profileMessages)
                .anySatisfy(message -> assertThat(message.getNotificationProfileUuids()).contains(profileUuid));

        notificationListener.processMessage(profileMessages.getFirst());
        // The persisted notification deep-links to the host object, not the comment the trigger evaluated
        assertThat(notificationRepository.findAll()).isNotEmpty().allSatisfy(notification -> {
            assertThat(notification.getTargetObjectType()).isEqualTo(Resource.RA_PROFILE);
            assertThat(notification.getTargetObjectIdentification()).isEqualTo(hostUuid.toString());
        });
    }

    @Test
    void unboundEventsPublishNoProfileDrivenMessages() throws Exception {
        Comment root = saveComment(hostUuid, null, actorUuid, "nobody listens");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, root, null));
        commentResolvedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_RESOLVED, root, true));

        assertThat(profileDrivenMessages()).isEmpty();
        // the actor is the only thread participant and the host has no owner, so no follow-ups either
        assertThat(followUpMessages()).isEmpty();
        assertThat(notificationRepository.findAll()).isEmpty();
    }

    @Test
    void replyDeliversInternalNotificationsToParticipantsExceptTheActor() throws Exception {
        UUID rootAuthor = UUID.randomUUID();
        UUID earlierReplier = UUID.randomUUID();
        Comment root = saveComment(hostUuid, null, rootAuthor, "root");
        saveComment(hostUuid, root.getUuid(), earlierReplier, "earlier reply");
        Comment reply = saveComment(hostUuid, root.getUuid(), actorUuid, "acting reply");

        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, reply, null));

        List<NotificationMessage> followUps = followUpMessages();
        assertThat(followUps).hasSize(1);
        assertThat(followUps.getFirst().getRecipients())
                .extracting(NotificationRecipient::getRecipientUuid)
                .containsExactlyInAnyOrder(rootAuthor, earlierReplier);

        notificationListener.processMessage(followUps.getFirst());
        assertThat(notificationRepository.findAll())
                .hasSize(2)
                .allSatisfy(notification -> assertThat(notification.getTargetObjectIdentification())
                        .isEqualTo(hostUuid.toString()));
    }

    @Test
    void resolvingDeliversToParticipantsWithTheActorInTheEventData() throws Exception {
        UUID rootAuthor = UUID.randomUUID();
        Comment root = saveComment(hostUuid, null, rootAuthor, "resolve me");
        saveComment(hostUuid, root.getUuid(), actorUuid, "participant resolves");

        commentResolvedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_RESOLVED, root, true));

        List<NotificationMessage> followUps = followUpMessages();
        assertThat(followUps).hasSize(1);
        assertThat(followUps.getFirst().getRecipients())
                .extracting(NotificationRecipient::getRecipientUuid)
                .containsExactly(rootAuthor);
        CommentEventData data = (CommentEventData) followUps.getFirst().getData();
        assertThat(data.getResolvedByUuid()).isEqualTo(actorUuid);
        assertThat(data.getResolved()).isTrue();
    }

    @Test
    void rootCommentNotifiesTheHostOwnerOnlyWhereAnAssociationExists() throws Exception {
        UUID ownerUuid = UUID.randomUUID();
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(Resource.RA_PROFILE);
        association.setObjectUuid(hostUuid);
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername("tst-owner");
        ownerAssociationRepository.save(association);

        Comment root = saveComment(hostUuid, null, actorUuid, "for the owner");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, root, null));

        List<NotificationMessage> followUps = followUpMessages();
        assertThat(followUps).hasSize(1);
        // The owner is resolved at publish time, so the message already carries them as a plain user
        assertThat(followUps.getFirst().getRecipients())
                .extracting(NotificationRecipient::getRecipientUuid)
                .containsExactly(ownerUuid);
        notificationListener.processMessage(followUps.getFirst());
        assertThat(notificationRepository.findAll()).hasSize(1);

        recordedMessages.clear();
        RaProfile ownerless = new RaProfile();
        ownerless.setName("tst-ra-profile-ownerless");
        UUID ownerlessUuid = raProfileRepository.save(ownerless).getUuid();
        Comment ownerlessRoot = saveComment(ownerlessUuid, null, actorUuid, "for nobody");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, ownerlessRoot, null));

        assertThat(followUpMessages()).isEmpty();
    }

    @Test
    void conditionScopedTriggerFiresForRootsAndSkipsReplies() throws Exception {
        UUID profileUuid = bindProfileTrigger(ResourceEvent.COMMENT_CREATED, null, null, rootsOnlyRule());

        Comment root = saveComment(hostUuid, null, actorUuid, "a root comment");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, root, null));

        assertThat(profileDrivenMessages())
                .anySatisfy(message -> assertThat(message.getNotificationProfileUuids()).contains(profileUuid));

        recordedMessages.clear();
        Comment reply = saveComment(hostUuid, root.getUuid(), UUID.randomUUID(), "a reply");
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, reply, null));

        assertThat(profileDrivenMessages()).isEmpty();
    }

    @Test
    void notificationsCarryNoCommentBodyWhileTheEventPayloadKeepsItVerbatim() throws Exception {
        String hostile = "<script>alert('x')</script> **bold** [link](javascript:alert(1)) ";
        String body = hostile + "a".repeat(600);
        UUID ownerUuid = UUID.randomUUID();
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(Resource.RA_PROFILE);
        association.setObjectUuid(hostUuid);
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername("tst-owner");
        ownerAssociationRepository.save(association);

        Comment root = saveComment(hostUuid, null, actorUuid, body);
        commentCreatedEventHandler.handleEvent(eventMessage(ResourceEvent.COMMENT_CREATED, root, null));

        NotificationMessage followUp = followUpMessages().getFirst();
        // The event payload keeps the raw Markdown source verbatim for operator-bound templates
        assertThat(((CommentEventData) followUp.getData()).getBody()).isEqualTo(body);

        notificationListener.processMessage(followUp);

        List<Notification> notifications = notificationRepository.findAll();
        assertThat(notifications).hasSize(1);
        Notification notification = notifications.getFirst();
        // The persisted notification points at the thread and never mirrors user-authored text
        assertThat(notification.getDetail()).isNull();
        assertThat(notification.getMessage()).doesNotContain("<script>");
        assertThat(commentRepository.findByUuid(root.getSecuredUuid()).orElseThrow().getBody()).hasSize(body.length());
    }
}
