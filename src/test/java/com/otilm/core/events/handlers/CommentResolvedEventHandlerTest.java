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
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.ResourceObjectAssociationService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CommentResolvedEventHandlerTest {

    private static final UUID HOST_UUID = UUID.randomUUID();
    private static final UUID ACTOR_UUID = UUID.randomUUID();

    private CommentRepository commentRepository;
    private ApplicationEventPublisher publisher;
    private AuthorizationEnforcer authorizationEnforcer;
    private ResourceObjectAssociationService associationService;
    private CommentResolvedEventHandler handler;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        commentRepository = mock(CommentRepository.class);
        publisher = mock(ApplicationEventPublisher.class);
        authorizationEnforcer = mock(AuthorizationEnforcer.class);
        when(authorizationEnforcer.isAuthorizedAs(any(), any(), any(), any())).thenReturn(true);
        associationService = mock(ResourceObjectAssociationService.class);

        handler = new CommentResolvedEventHandler(commentRepository, mock(TriggerEvaluator.class));
        handler.setResourceObjectAssociationService(associationService);
        handler.setApplicationEventPublisher(publisher);
        handler.setAuthorizationEnforcer(authorizationEnforcer);
    }

    private EventContext<Comment> context(Comment root) {
        return context(root, true);
    }

    private EventContext<Comment> context(Comment root, boolean resolved) {
        CommentEventData eventData = new CommentEventData();
        eventData.setCommentUuid(root.getUuid());
        eventData.setResource(root.getResource());
        eventData.setObjectUuid(root.getObjectUuid());
        eventData.setBody(root.getBody());
        eventData.setResolved(resolved);
        eventData.setResolvedByUuid(ACTOR_UUID);
        EventMessage eventMessage = new EventMessage(ResourceEvent.COMMENT_RESOLVED, Resource.COMMENT, root.getUuid(),
                null, null, eventData, ACTOR_UUID, null);
        return new EventContext<>(eventMessage, null, root, eventData);
    }

    private Comment root() {
        Comment root = new Comment();
        root.setUuid(UUID.randomUUID());
        root.setResource(Resource.RA_PROFILE);
        root.setObjectUuid(HOST_UUID);
        root.setAuthorUuid(UUID.randomUUID());
        root.setAuthorUsername("tst-author");
        root.setBody("resolve me");
        return root;
    }

    @Test
    void resolutionNotifiesThreadParticipantsExceptTheActor() {
        Comment root = root();
        UUID participant = UUID.randomUUID();
        when(commentRepository.findThreadParticipantUuids(root.getUuid()))
                .thenReturn(List.of(root.getAuthorUuid(), participant, ACTOR_UUID));

        handler.sendFollowUpEventsNotifications(context(root));

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        NotificationMessage message = captor.getValue();
        assertEquals(Resource.RA_PROFILE, message.getResource());
        assertEquals(HOST_UUID, message.getObjectUuid());
        assertEquals(List.of(root.getAuthorUuid(), participant),
                message.getRecipients().stream().map(NotificationRecipient::getRecipientUuid).toList());
        assertEquals(RecipientType.USER, message.getRecipients().getFirst().getRecipientType());
    }

    @Test
    void resolutionByTheOnlyParticipantPublishesNothing() {
        Comment root = root();
        when(commentRepository.findThreadParticipantUuids(root.getUuid())).thenReturn(List.of(ACTOR_UUID));

        handler.sendFollowUpEventsNotifications(context(root));

        verifyNoInteractions(publisher);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void resolutionChangeNotifiesTheHostObjectOwnerWhoHasNotJoinedTheThread(boolean resolved) {
        Comment root = root();
        UUID ownerUuid = UUID.randomUUID();
        when(associationService.getOwner(Resource.RA_PROFILE, HOST_UUID))
                .thenReturn(new NameAndUuidDto(ownerUuid.toString(), "tst-owner"));
        when(commentRepository.findThreadParticipantUuids(root.getUuid()))
                .thenReturn(List.of(root.getAuthorUuid(), ACTOR_UUID));

        handler.sendFollowUpEventsNotifications(context(root, resolved));

        ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
        verify(publisher).publishEvent(captor.capture());
        assertEquals(List.of(ownerUuid, root.getAuthorUuid()),
                captor.getValue().getRecipients().stream().map(NotificationRecipient::getRecipientUuid).toList());
    }
}
