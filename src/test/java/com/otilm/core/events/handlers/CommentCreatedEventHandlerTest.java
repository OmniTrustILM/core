package com.otilm.core.events.handlers;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.ResourceObjectAssociationService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CommentCreatedEventHandlerTest {

    private static final UUID HOST_UUID = UUID.randomUUID();
    private static final UUID ACTOR_UUID = UUID.randomUUID();

    private CommentRepository commentRepository;
    private AuthorizationEnforcer authorizationEnforcer;
    private ResourceObjectAssociationService associationService;
    private ApplicationEventPublisher publisher;
    private CommentCreatedEventHandler handler;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        commentRepository = mock(CommentRepository.class);
        associationService = mock(ResourceObjectAssociationService.class);
        publisher = mock(ApplicationEventPublisher.class);

        authorizationEnforcer = mock(AuthorizationEnforcer.class);
        when(authorizationEnforcer.isAuthorizedAs(any(), any(), any(), any())).thenReturn(true);

        handler = new CommentCreatedEventHandler(commentRepository, mock(TriggerEvaluator.class));
        handler.setResourceObjectAssociationService(associationService);
        handler.setApplicationEventPublisher(publisher);
        handler.setAuthorizationEnforcer(authorizationEnforcer);
    }

    private Comment comment(UUID parentUuid) {
        Comment comment = new Comment();
        comment.setUuid(UUID.randomUUID());
        comment.setResource(Resource.RA_PROFILE);
        comment.setObjectUuid(HOST_UUID);
        comment.setParentUuid(parentUuid);
        comment.setAuthorUuid(ACTOR_UUID);
        comment.setAuthorUsername("tst-author");
        comment.setBody("a request");
        return comment;
    }

    private EventContext<Comment> context(Comment comment) {
        CommentEventData eventData = new CommentEventData();
        eventData.setCommentUuid(comment.getUuid());
        eventData.setParentUuid(comment.getParentUuid());
        eventData.setResource(comment.getResource());
        eventData.setObjectUuid(comment.getObjectUuid());
        eventData.setBody(comment.getBody());
        EventMessage eventMessage = new EventMessage(ResourceEvent.COMMENT_CREATED, Resource.COMMENT, comment.getUuid(),
                null, null, eventData, ACTOR_UUID, null);
        return new EventContext<>(eventMessage, null, comment, eventData);
    }

    @Test
    void rootNotifiesTheHostObjectOwner() {
        UUID ownerUuid = UUID.randomUUID();
        when(associationService.getOwner(Resource.RA_PROFILE, HOST_UUID))
                .thenReturn(new NameAndUuidDto(ownerUuid.toString(), "tst-owner"));

        handler.sendFollowUpEventsNotifications(context(comment(null)));

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        NotificationMessage message = captor.getValue();
        assertNull(message.getNotificationProfileUuids());
        assertEquals(Resource.RA_PROFILE, message.getResource());
        assertEquals(HOST_UUID, message.getObjectUuid());
        assertEquals(1, message.getRecipients().size());
        assertEquals(RecipientType.USER, message.getRecipients().getFirst().getRecipientType());
        assertEquals(ownerUuid, message.getRecipients().getFirst().getRecipientUuid());
    }

    @Test
    void rootWithoutHostOwnerPublishesNothing() {
        when(associationService.getOwner(Resource.RA_PROFILE, HOST_UUID)).thenReturn(null);

        handler.sendFollowUpEventsNotifications(context(comment(null)));

        verifyNoInteractions(publisher);
    }

    @Test
    void rootPostedByTheOwnerIsNotSelfNotified() {
        when(associationService.getOwner(Resource.RA_PROFILE, HOST_UUID))
                .thenReturn(new NameAndUuidDto(ACTOR_UUID.toString(), "tst-author"));

        handler.sendFollowUpEventsNotifications(context(comment(null)));

        verifyNoInteractions(publisher);
    }

    @Test
    void replyNotifiesThreadParticipantsExceptTheActor() {
        UUID rootUuid = UUID.randomUUID();
        UUID participantB = UUID.randomUUID();
        UUID participantC = UUID.randomUUID();
        when(commentRepository.findThreadParticipantUuids(rootUuid))
                .thenReturn(List.of(ACTOR_UUID, participantB, participantC));

        handler.sendFollowUpEventsNotifications(context(comment(rootUuid)));

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        assertEquals(List.of(participantB, participantC),
                captor.getValue().getRecipients().stream().map(NotificationRecipient::getRecipientUuid).toList());
        assertEquals(RecipientType.USER, captor.getValue().getRecipients().getFirst().getRecipientType());
    }

    @Test
    void replyDoesNotNotifyParticipantsWhoCanNoLongerReadTheHost() {
        UUID rootUuid = UUID.randomUUID();
        UUID stillAllowed = UUID.randomUUID();
        UUID revoked = UUID.randomUUID();
        when(commentRepository.findThreadParticipantUuids(rootUuid))
                .thenReturn(List.of(ACTOR_UUID, stillAllowed, revoked));
        when(authorizationEnforcer.isAuthorizedAs(eq(revoked), any(), any(), any())).thenReturn(false);

        handler.sendFollowUpEventsNotifications(context(comment(rootUuid)));

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        assertEquals(List.of(stillAllowed),
                captor.getValue().getRecipients().stream().map(NotificationRecipient::getRecipientUuid).toList());
        verify(authorizationEnforcer)
                .isAuthorizedAs(eq(stillAllowed), eq(Resource.RA_PROFILE), eq(ResourceAction.DETAIL),
                        argThat(uuid -> HOST_UUID.equals(uuid.getValue())));
    }

    @Test
    void replyWithNoOtherParticipantsPublishesNothing() {
        UUID rootUuid = UUID.randomUUID();
        when(commentRepository.findThreadParticipantUuids(rootUuid)).thenReturn(List.of(ACTOR_UUID));

        handler.sendFollowUpEventsNotifications(context(comment(rootUuid)));

        verifyNoInteractions(publisher);
    }
}
